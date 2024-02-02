// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) Felix Geyer <debfx@fobos.de>

package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/gobwas/glob"
	"golang.org/x/sys/unix"
)

type passHttpProxyChild struct {
	Settings   settingsStruct
	SocketPath string
	SyncFd     uintptr
}

func encodePassHttpProxyChild(settings settingsStruct, socketPath string, syncFd uintptr) ([]byte, error) {
	data := passHttpProxyChild{settings, socketPath, syncFd}
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(data); err != nil {
		return []byte{}, err
	}
	return b.Bytes(), nil
}

func decodePassHttpProxyChild(input []byte) (settingsStruct, string, uintptr, error) {
	output := passHttpProxyChild{}
	b := bytes.Buffer{}
	b.Write(input)
	d := gob.NewDecoder(&b)
	if err := d.Decode(&output); err != nil {
		return settingsStruct{}, "", 0, err
	}
	return output.Settings, output.SocketPath, output.SyncFd, nil
}

func isHostAllowed(hostname string, allowedHosts []glob.Glob) bool {
	hostnameWithoutPort := strings.Split(hostname, ":")[0]

	for _, g := range allowedHosts {
		if g.Match(hostnameWithoutPort) {
			return true
		}
	}

	return false
}

func validateAllowedHosts(settings settingsStruct) error {
	for _, hostname := range settings.AllowedHosts {
		_, err := glob.Compile(hostname)
		if err != nil {
			return err
		}
	}

	return nil
}

func setupHttpProxy(originalSettings settingsStruct) (proxyPipe uintptr, proxyMount mount, cleanupFile string, err error) {
	runtimeDir, err := getUserRuntimeDir()
	if err != nil {
		return
	}

	proxySocketDir := path.Join(runtimeDir, ".http-proxy")
	if err = os.MkdirAll(proxySocketDir, 0750); err != nil {
		return
	}
	proxySocketFile, err := os.CreateTemp(proxySocketDir, "http-filter-proxy-")
	if err != nil {
		return
	}
	cleanupFile = proxySocketFile.Name()
	err = proxySocketFile.Close()
	if err != nil {
		return
	}

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return
	}
	// pass pipeW to http proxy and close it in this process afterwards
	if err = clearCloseOnExec(pipeW.Fd()); err != nil {
		return
	}
	defer pipeW.Close()

	encodedParams, err := encodePassHttpProxyChild(originalSettings, proxySocketFile.Name(), pipeW.Fd())
	if err != nil {
		return
	}
	dataFile, err := getDataFileBytes(encodedParams)
	if err != nil {
		return
	}
	defer dataFile.Close()

	rawMountOptions, err := getDefaultOptions()
	if err != nil {
		return
	}
	rawMountOptions.Rw = append(rawMountOptions.Rw, proxySocketDir)
	mountOptions, err := parseRawMountOptions(rawMountOptions)
	if err != nil {
		return
	}

	settings := getDefaultSettings()
	settings.Cwd = "/"
	settings.Command = []string{"/proc/self/exe", "http-proxy", strconv.Itoa(int(dataFile.Fd()))}
	settings.OverrideArg0 = os.Args[0]
	settings.Network = true
	settings.Debug = originalSettings.Debug

	_, err = run(settings, mountOptions, os.Environ(), true)
	if err != nil {
		return
	}

	// wait for http proxy to be initialized
	dataRead := make([]byte, 1)
	bytesRead, err := pipeR.Read(dataRead)
	if err != nil {
		return
	}
	if bytesRead != 1 {
		err = fmt.Errorf("failed to initialize http proxy, syncing failed")
		return
	}

	proxyPipe = pipeR.Fd()
	proxyMount = mount{Type: mountTypeBindRw, Path: path.Join(runtimeDir, "http-proxy"), Other: proxySocketFile.Name()}
	return
}

func runHttpProxy() error {
	dataFd, _ := strconv.Atoi(os.Args[2])
	dataFile := os.NewFile(uintptr(dataFd), "")
	paramsBytes, _ := io.ReadAll(dataFile)
	if err := dataFile.Close(); err != nil {
		return fmt.Errorf("failed to close the parameters file: %w", err)
	}

	settings, socketPath, syncFd, _ := decodePassHttpProxyChild(paramsBytes)

	var allowedHostGlobs []glob.Glob
	for _, hostname := range settings.AllowedHosts {
		allowedHostGlobs = append(allowedHostGlobs, glob.MustCompile(hostname, '.'))
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = settings.Debug

	proxy.OnRequest().DoFunc(
		func(request *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if isHostAllowed(request.Host, allowedHostGlobs) {
				if settings.Debug {
					fmt.Printf("HTTP ALLOWED %s\n", request.Host)
				}
				return request, nil
			}

			fmt.Printf("HTTP REJECTED %s\n", request.Host)
			return request, goproxy.NewResponse(request, goproxy.ContentTypeText, http.StatusForbidden, "Forbidden")
		})

	proxy.OnRequest().HandleConnectFunc(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			if isHostAllowed(host, allowedHostGlobs) {
				if settings.Debug {
					fmt.Printf("CONNECT ALLOWED %s\n", host)
				}
				return goproxy.OkConnect, host
			}

			fmt.Printf("CONNECT REJECTED %s\n", host)
			return goproxy.RejectConnect, host
		})

	err := os.Remove(socketPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var wg sync.WaitGroup
	httpServer := &http.Server{Handler: proxy}

	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := httpServer.Serve(unixListener)
		if err != nil && err != http.ErrServerClosed {
			fmt.Println(err)
		}
	}()
	defer unixListener.Close()

	syncFile := os.NewFile(syncFd, "pipe")
	_, err = syncFile.Write([]byte("x"))
	if err != nil {
		return err
	}

	go func() {
		fds := []unix.PollFd{{Fd: int32(syncFd), Events: 0}}
		var err error
		for {
			_, err = unix.Poll(fds, -1)
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		if err != nil {
			fmt.Printf("error polling the sync pipe: %v\n", err)
		}
		// "This bit [POLLERR] is also set for a file descriptor referring to the write end of a pipe when the read end has been closed."
		if (err != nil) || (fds[0].Revents&unix.POLLHUP != 0) || (fds[0].Revents&unix.POLLERR != 0) {
			err = httpServer.Shutdown(context.Background())
			if err != nil {
				fmt.Println(err)
			}
		}
	}()

	wg.Wait()

	return nil
}

func forwardConnection(localConn net.Conn, proxyServerPath string) {
	proxyServerConn, err := net.Dial("unix", proxyServerPath)
	if err != nil {
		fmt.Printf("Failed to connect to unix socket of the http proxy: %v\n", err)
		return
	}

	go func() {
		_, err = io.Copy(proxyServerConn, localConn)
		if err != nil {
			if !errors.Is(err, unix.EPIPE) {
				fmt.Printf("Forwarding from http proxy unix socket to local tcp port failed: %v\n", err)
			}
			proxyServerConn.Close()
			localConn.Close()
		}
	}()

	go func() {
		_, err = io.Copy(localConn, proxyServerConn)
		if err != nil {
			if !errors.Is(err, unix.EPIPE) {
				fmt.Printf("Forwarding from local tcp port to http proxy unix socket failed: %v\n", err)
			}
			proxyServerConn.Close()
			localConn.Close()
		}
	}()
}

func runHttpProxyForwarder() error {
	runtimeDir, err := getUserRuntimeDir()
	if err != nil {
		return err
	}
	proxyServerPath := path.Join(runtimeDir, "http-proxy")

	tcpListener, err := net.Listen("tcp", ":18080")
	if err != nil {
		return err
	}
	for {
		localConn, err := tcpListener.Accept()
		if err != nil {
			fmt.Printf("error: listen.Accept failed: %v", err)
			continue
		}
		go forwardConnection(localConn, proxyServerPath)
	}
}
