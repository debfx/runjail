// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) Felix Geyer <debfx@fobos.de>

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
)

func setupDbusProxy(originalSettings settingsStruct) (proxyPipe uintptr, dbusMount mount, cleanupFile string, err error) {
	runtimeDir, err := getUserRuntimeDir()
	if err != nil {
		return
	}

	proxySocketDir := path.Join(runtimeDir, ".dbus-proxy")
	if err = os.MkdirAll(proxySocketDir, 0750); err != nil {
		return
	}
	proxySocketFile, err := os.CreateTemp(proxySocketDir, "session-bus-proxy-")
	if err != nil {
		return
	}
	cleanupFile = proxySocketFile.Name()
	err = proxySocketFile.Close()
	if err != nil {
		return
	}

	hostSocketPath := path.Join(runtimeDir, "bus")
	dbusProxyBin, err := exec.LookPath("xdg-dbus-proxy")
	if err != nil {
		return
	}

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return
	}
	// pass pipeW to xdg-dbus-proxy and close it in this process afterwards
	if err = clearCloseOnExec(pipeW.Fd()); err != nil {
		return
	}
	defer pipeW.Close()

	dbusProxyArgs := []string{"--fd=" + strconv.Itoa(int(pipeW.Fd())), "unix:path=" + hostSocketPath, proxySocketFile.Name(), "--filter"}

	// DBus filter explanation: https://bugs.freedesktop.org/show_bug.cgi?id=101902
	for _, name := range originalSettings.DbusOwn {
		dbusProxyArgs = append(dbusProxyArgs, "--own="+name)
	}

	for _, name := range originalSettings.DbusTalk {
		dbusProxyArgs = append(dbusProxyArgs, "--talk="+name)
	}

	for _, name := range originalSettings.DbusCall {
		dbusProxyArgs = append(dbusProxyArgs, "--call="+name)
	}

	for _, name := range originalSettings.DbusBroadcast {
		dbusProxyArgs = append(dbusProxyArgs, "--broadcast="+name)
	}

	if originalSettings.Debug {
		dbusProxyArgs = append(dbusProxyArgs, "--log")
		printCmdArgs := strings.Join(dbusProxyArgs, " ")
		fmt.Fprintf(os.Stderr, "Running: dbus-proxy %s\n", printCmdArgs)
	}

	argsFile, err := getDataFileBytes(append([]byte(strings.Join(dbusProxyArgs, "\x00")), []byte("\x00")...))
	if err != nil {
		return
	}
	defer argsFile.Close()

	rawMountOptions, err := getDefaultOptions()
	if err != nil {
		return
	}
	rawMountOptions.Rw = append(rawMountOptions.Rw, hostSocketPath)
	rawMountOptions.Rw = append(rawMountOptions.Rw, proxySocketDir)
	rawMountOptions.Ro = append(rawMountOptions.Ro, dbusProxyBin)
	mountOptions, err := parseRawMountOptions(rawMountOptions)
	if err != nil {
		return
	}

	settings := getDefaultSettings()
	settings.Cwd = "/"
	settings.Command = []string{dbusProxyBin, "--args=" + strconv.Itoa(int(argsFile.Fd()))}
	settings.Network = false
	settings.Debug = originalSettings.Debug

	_, err = run(settings, mountOptions, os.Environ(), true)
	if err != nil {
		return
	}

	dataRead := make([]byte, 1)
	bytesRead, err := pipeR.Read(dataRead)
	if err != nil {
		return
	}
	if bytesRead != 1 {
		err = fmt.Errorf("failed to initialize dbus proxy, syncing failed")
		return
	}

	proxyPipe = pipeR.Fd()
	dbusMount = mount{Type: mountTypeBindRw, Path: hostSocketPath, Other: proxySocketFile.Name()}
	return
}
