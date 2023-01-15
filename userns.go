// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) 2020-2022 Felix Geyer <debfx@fobos.de>

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	securejoin "github.com/cyphar/filepath-securejoin"

	"golang.org/x/sys/unix"
)

type passUsernsChildStruct struct {
	Settings     settingsStruct
	Mounts       []mount
	ReturnCodeFd int
}

func encodePassUsernsChild(data passUsernsChildStruct) ([]byte, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(data); err != nil {
		return []byte{}, err
	}
	return b.Bytes(), nil
}

func decodePassUsernsChild(input []byte) (passUsernsChildStruct, error) {
	output := passUsernsChildStruct{}
	b := bytes.Buffer{}
	b.Write(input)
	d := gob.NewDecoder(&b)
	if err := d.Decode(&output); err != nil {
		return passUsernsChildStruct{}, err
	}
	return output, nil
}

func usernsRun(exe string, settings settingsStruct, mounts []mount, environ []string, fork bool) (int, error) {
	var unshareFlags uintptr = unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID
	if !settings.Ipc {
		unshareFlags = unshareFlags | unix.CLONE_NEWIPC
	}
	if !settings.Network {
		unshareFlags = unshareFlags | unix.CLONE_NEWNET
	}

	allCaps, err := getAllCaps()
	if err != nil {
		return 0, err
	}

	passStruct := passUsernsChildStruct{
		Settings:     settings,
		Mounts:       mounts,
		ReturnCodeFd: -1,
	}

	var pipeR, pipeW *os.File
	if !fork {
		pipeR, pipeW, err = os.Pipe()
		if err != nil {
			return 0, err
		}
		if err = clearCloseOnExec(pipeW.Fd()); err != nil {
			return 0, err
		}
		passStruct.ReturnCodeFd = int(pipeW.Fd())
	}

	encodedParams, err := encodePassUsernsChild(passStruct)
	if err != nil {
		return 0, fmt.Errorf("failed to serialize settings: %w", err)
	}
	dataFile, err := getDataFileBytes(encodedParams)
	if err != nil {
		return 0, err
	}
	defer dataFile.Close()

	for _, fd := range settings.SyncFds {
		if err := clearCloseOnExec(fd); err != nil {
			return 0, err
		}
	}

	cmd := exec.Cmd{
		Path:   exe,
		Args:   []string{os.Args[0], "userns-child", strconv.Itoa(int(dataFile.Fd()))},
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Env:    environ,
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags: unshareFlags,
			UidMappings: []syscall.SysProcIDMap{
				{
					ContainerID: os.Getuid(),
					HostID:      os.Getuid(),
					Size:        1,
				},
			},
			GidMappings: []syscall.SysProcIDMap{
				{
					ContainerID: os.Getgid(),
					HostID:      os.Getgid(),
					Size:        1,
				},
			},
			GidMappingsEnableSetgroups: false,
			AmbientCaps:                allCaps,
		},
	}

	err = cmd.Start()
	if pipeW != nil {
		pipeW.Close()
	}
	for _, fd := range settings.SyncFds {
		unix.Close(int(fd))
	}
	if err != nil {
		if exitErr, isExitErr := err.(*exec.ExitError); isExitErr {
			return exitErr.ProcessState.ExitCode(), nil
		}
		return 0, fmt.Errorf("failed to start runjail in new namespace: %w", err)
	}

	if fork {
		return 0, nil
	}

	dataRead := make([]byte, 1)
	bytesRead, err := pipeR.Read(dataRead)
	if err != nil {
		return 0, fmt.Errorf("failed to wait for child: %w", err)
	}

	if bytesRead != 1 {
		return 0, fmt.Errorf("failed to wait for child: no response")
	}

	return int(dataRead[0]), nil
}

func mountPrivatePropagation() error {
	return unix.Mount("none", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
}

func getCapLastCap() (uintptr, error) {
	lastCapByteString, err := ioutil.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, err
	}

	lastCap, err := strconv.Atoi(strings.TrimSpace(string(lastCapByteString)))
	if err != nil {
		return 0, err
	}

	return uintptr(lastCap), nil
}

func getAllCaps() ([]uintptr, error) {
	result := []uintptr{}
	lastCap, err := getCapLastCap()
	if err != nil {
		return result, err
	}

	for cap := uintptr(0); cap <= lastCap; cap++ {
		result = append(result, cap)
	}

	return result, nil
}

func dropCapabilities() error {
	// syscall expects an array of 2 on 64-bit archs
	cap := [2]unix.CapUserData{}
	cap[0] = unix.CapUserData{
		Effective:   0,
		Permitted:   0,
		Inheritable: 0,
	}
	return unix.Capset(
		&unix.CapUserHeader{
			Version: unix.LINUX_CAPABILITY_VERSION_3,
		},
		&cap[0],
	)
}

func dropCapabilityBoundingSet() error {
	lastCap, err := getCapLastCap()
	if err != nil {
		return err
	}

	for cap := uintptr(0); cap <= lastCap; cap++ {
		err = unix.Prctl(unix.PR_CAPBSET_DROP, cap, 0, 0, 0)
		if err != nil {
			return err
		}
	}

	return nil
}

func restrictUserNamespaces() error {
	err := ioutil.WriteFile("/proc/sys/user/max_user_namespaces", []byte("0"), 0644)
	if err != nil {
		return fmt.Errorf("failed to set user.max_user_namespaces sysctl: %w", err)
	}

	return nil
}

func mountTmpfs(path string, mode string, readOnly bool) error {
	flags := unix.MS_REC | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOATIME
	if err := unix.Mount("tmpfs", path, "tmpfs", uintptr(flags), "mode="+mode); err != nil {
		return err
	}

	if readOnly {
		if err := remountReadOnly(path, flags); err != nil {
			return err
		}
	}

	return nil
}

func mountProc(path string) error {
	return unix.Mount("proc", path, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
}

func mountDevPts(path string) error {
	return unix.Mount("devpts", path, "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=620")
}

func remountReadOnly(path string, existingFlags int) error {
	return unix.Mount(path, path, "", uintptr(existingFlags|unix.MS_REMOUNT|unix.MS_REC|unix.MS_BIND|unix.MS_RDONLY), "")
}

func mountBind(source string, target string, readOnly bool, debug bool) error {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return err
	}

	if sourceInfo.IsDir() {
		if err := os.MkdirAll(target, 0700); err != nil {
			return err
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if _, err := os.Stat(target); os.IsNotExist(err) {
			if err := ioutil.WriteFile(target, []byte{}, 0600); err != nil {
				return err
			}
		}
	}

	if err := unix.Mount(source, target, "", unix.MS_REC|unix.MS_BIND, ""); err != nil {
		return err
	}

	// recursively remount everything beneath the given path
	// doing that on `target` with MS_REC is not enough
	if readOnly {
		mountInfo, err := parseMountInfo(target, "/newroot/proc/self/mountinfo")
		if err != nil {
			return fmt.Errorf("failed to parse mountinfo: %w", err)
		}

		for _, mountEntry := range mountInfo {
			// Skip mountpoints that are shadowed or we have otherwise no access to
			// since remounting them could return an error.
			// If we can't stat the mountpoint we shouldn't be able to traverse it so
			// remounting isn't necessary.
			var mountPointStat unix.Stat_t
			err = unix.Stat(mountEntry.mountPoint, &mountPointStat)
			if err != nil {
				if os.IsNotExist(err) || os.IsPermission(err) {
					if debug {
						// strip /newroot/ from mountEntry.mountPoint
						fmt.Printf("Skipped remounting as read-only: %s\n", mountEntry.mountPoint[8:])
					}
					continue
				} else {
					return fmt.Errorf("failed to stat %s: %w", mountEntry.mountPoint, err)
				}
			}

			if err := remountReadOnly(mountEntry.mountPoint, mountEntry.mountFlags()); err != nil {
				return fmt.Errorf("failed to remount %s read-only: %w", mountEntry.mountPoint, err)
			}
		}
	}
	return nil
}

func reapChildren(mainPid int, helperPids []int, syncFile *os.File) error {
	var wstatus unix.WaitStatus
	var err error
	var diedPid int
	mainExited := false

	for {
		// reap any terminated child
		for {
			diedPid, err = unix.Wait4(-1, &wstatus, 0, nil)
			if err != unix.EINTR {
				break
			}
		}

		if err == unix.ECHILD {
			// no more children to wait upon
			return nil
		}

		helperPids = removeIntFromSlice(diedPid, helperPids)

		if err == nil && diedPid == mainPid {
			var exitCode byte
			if wstatus.Exited() {
				exitCode = byte(wstatus.ExitStatus())
			} else if wstatus.Signaled() {
				exitCode = byte(128 + int(wstatus.Signal()))
			} else {
				exitCode = 255
			}

			if syncFile != nil {
				_, err = syncFile.Write([]byte{exitCode})
				if err != nil {
					return fmt.Errorf("failed to write exit code to pipe: %w", err)
				}
				err = syncFile.Close()
				if err != nil {
					return fmt.Errorf("failed to write exit code pipe: %w", err)
				}
			}

			mainExited = true
		}

		if mainExited && len(helperPids) != 0 {
			runningPids, err := getAllRunningPids()
			if err != nil {
				return fmt.Errorf("failed to read all processes: %w", err)
			}

			allNonHelperExited := true
			for _, pid := range runningPids {
				if pid != 1 && !isIntInSlice(pid, helperPids) {
					allNonHelperExited = false
					break
				}
			}

			if allNonHelperExited {
				// only helper processes left, terminate them
				for _, pid := range helperPids {
					err = unix.Kill(pid, unix.SIGKILL)
					if err != nil && err != unix.ESRCH {
						return fmt.Errorf("failed to kill helper process: %w", err)
					}
				}
			}
		}
	}
}

func usernsChild() error {
	dataFd, _ := strconv.Atoi(os.Args[2])
	dataFile := os.NewFile(uintptr(dataFd), "")
	paramsBytes, _ := ioutil.ReadAll(dataFile)
	if err := dataFile.Close(); err != nil {
		return fmt.Errorf("failed to close the parameters file: %w", err)
	}

	passStruct, err := decodePassUsernsChild(paramsBytes)
	if err != nil {
		return fmt.Errorf("failed to deserialize settings: %w", err)
	}
	settings := passStruct.Settings
	mounts := passStruct.Mounts

	if passStruct.ReturnCodeFd != -1 {
		if err := setCloseOnExec(uintptr(passStruct.ReturnCodeFd)); err != nil {
			return fmt.Errorf("failed to set O_CLOEXEC on fd %d: %w", passStruct.ReturnCodeFd, err)
		}
	}
	for _, fd := range settings.SyncFds {
		if err := setCloseOnExec(fd); err != nil {
			return fmt.Errorf("failed to set O_CLOEXEC on fd %d: %w", fd, err)
		}
	}

	if err := mountPrivatePropagation(); err != nil {
		return fmt.Errorf("disabling mount propagation failed: %w", err)
	}

	tmpDir := os.TempDir()
	if err := mountTmpfs(tmpDir, "700", false); err != nil {
		return fmt.Errorf("mount tmpfs on base dir failed: %w", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		return fmt.Errorf("chdir to tmp dir failed: %w", err)
	}

	if err := os.Mkdir("newroot", 0755); err != nil {
		return fmt.Errorf("failed to make newroot directory: %w", err)
	}
	// bind mount on itself so it still exists when tmpDir is unmounted
	if err := unix.Mount("newroot", "newroot", "", unix.MS_REC|unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("failed to bind-mount newroot: %w", err)
	}

	if err := os.Mkdir("oldroot", 0755); err != nil {
		return fmt.Errorf("failed to make oldroot directory: %w", err)
	}
	if err := unix.PivotRoot(tmpDir, "oldroot"); err != nil {
		return fmt.Errorf("pivot_root to temporary dir failed: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir / into temporary root dir failed: %w", err)
	}

	// create a file and a directory that we can mount over each mountTypeHide entry,
	// depending on what type it is
	hideFileFd, err := os.OpenFile("/hidefile", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0000)
	if err != nil {
		return fmt.Errorf("creating /hidefile failed: %w", err)
	}
	hideFile := hideFileFd.Name()
	hideFileFd.Close()
	hideDir := "/hidedir"
	if err := os.Mkdir(hideDir, 0000); err != nil {
		return fmt.Errorf("creating /hidedir failed: %w", err)
	}

	if err := os.Mkdir(path.Join("newroot", "proc"), 0550); err != nil {
		return fmt.Errorf("creating proc dir failed: %w", err)
	}
	if err := mountProc(path.Join("newroot", "proc")); err != nil {
		return fmt.Errorf("mount proc failed: %w", err)
	}

	if err := os.MkdirAll(path.Join("newroot", "dev/pts"), 0550); err != nil {
		return fmt.Errorf("creating dev/pts dir failed: %w", err)
	}
	if err := mountDevPts(path.Join("newroot", "dev", "pts")); err != nil {
		return fmt.Errorf("mount devpts failed: %w", err)
	}

	for _, mount := range mounts {
		oldDir := path.Join("/oldroot", mount.Other)
		// mount() would follow symlinks, so resolve the target ourselves with the correct root dir
		// this has the added advantage that we can try to create the correct parent dirs beforehand
		newDir, err := securejoin.SecureJoin("/newroot", mount.Path)
		if err != nil {
			return err
		}
		newDirRelative := newDir[8:]
		if settings.Debug && path.Join("/newroot", mount.Path) != newDir {
			fmt.Printf("Changing mount target from %s to %s\n", mount.Path, newDirRelative)
		}

		switch mount.Type {
		case mountTypeBindRo:
			if settings.Debug {
				fmt.Printf("Bind-mounting (read-only) %s on %s\n", mount.Other, newDirRelative)
			}
			if err := mountBind(oldDir, newDir, true, settings.Debug); err != nil {
				return err
			}
		case mountTypeBindRw:
			if settings.Debug {
				fmt.Printf("Bind-mounting %s on %s\n", mount.Other, newDirRelative)
			}
			if err := mountBind(oldDir, newDir, false, settings.Debug); err != nil {
				return err
			}
		case mountTypeHide:
			if settings.Debug {
				fmt.Printf("Mounting inaccessible tmpfs on %s\n", newDirRelative)
			}

			newDirInfo, err := os.Stat(newDir)
			if err != nil {
				if mount.Optional && errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}

			if newDirInfo.IsDir() {
				if err := mountBind(hideDir, newDir, true, settings.Debug); err != nil {
					return err
				}
			} else {
				if err := mountBind(hideFile, newDir, true, settings.Debug); err != nil {
					return err
				}
			}
		case mountTypeEmpty:
			if settings.Debug {
				fmt.Printf("Mounting empty tmpfs on %s\n", newDirRelative)
			}
			if err := os.MkdirAll(newDir, 0700); err != nil {
				return fmt.Errorf("creating directory failed: %w", err)
			}
			if err := mountTmpfs(newDir, "700", false); err != nil {
				return fmt.Errorf("mounting tmpfs on %s failed: %w", newDir, err)
			}
		case mountTypeSymlink:
			if settings.Debug {
				fmt.Printf("Creating symlink %s -> %s\n", newDirRelative, mount.Other)
			}
			if err := os.MkdirAll(filepath.Dir(newDir), 0700); err != nil {
				return fmt.Errorf("creating directory failed: %w", err)
			}
			// use mount.Other instead of oldDir here since we don't to change the symlink target
			if err := os.Symlink(mount.Other, newDir); err != nil {
				return fmt.Errorf("creating symlink failed: %w", err)
			}
		case mountTypeFileData:
			if settings.Debug {
				fmt.Printf("Creating %s from data file\n", newDirRelative)
			}

			tmpFile, err := ioutil.TempFile("/", "bindfile")
			if err != nil {
				return err
			}

			data, _ := base64.StdEncoding.DecodeString(mount.Other)
			_, err = tmpFile.Write(data)
			if err != nil {
				return err
			}
			tmpFile.Close()

			if err := os.MkdirAll(filepath.Dir(newDir), 0700); err != nil {
				return fmt.Errorf("creating directory failed: %w", err)
			}
			if err := mountBind(tmpFile.Name(), newDir, true, settings.Debug); err != nil {
				return err
			}
			if err := os.Remove(tmpFile.Name()); err != nil {
				return err
			}
		default:
			panic("")
		}
	}

	// not a security measure, but it seems sane to not have the root dir user-writable
	if err := os.Chmod("/newroot", 0555); err != nil {
		return fmt.Errorf("chmod / on new root failed: %w", err)
	}

	// no need to keep those around
	if err := os.Remove("/hidefile"); err != nil {
		return fmt.Errorf("failed to remove hidefile: %w", err)
	}
	if err := os.Remove("/hidedir"); err != nil {
		return fmt.Errorf("failed to rmeove hidedir: %w", err)
	}

	// make sure the mount is private so we don't proprage the umount() to the outside
	if err := unix.Mount("oldroot", "oldroot", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("failed to make oldroot mount private: %w", err)
	}
	if err := unix.Unmount("oldroot", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("failed to unmount oldroot: %w", err)
	}

	// open our temporary root dir so we can unmount it once newroot is "/"
	tmpRootFd, err := unix.Open("/", unix.O_DIRECTORY, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("failed to open temorary root directory: %w", err)
	}
	if err := os.Chdir("newroot"); err != nil {
		return fmt.Errorf("failed to chdir into newroot: %w", err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root into newroot failed: %w", err)
	}

	if err := unix.Fchdir(tmpRootFd); err != nil {
		return fmt.Errorf("failed to chdir into temporary root fd: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("failed to unmount temporary root tmpfs: %w", err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir / in new root failed: %w", err)
	}
	if err := unix.Close(tmpRootFd); err != nil {
		return fmt.Errorf("failed to close temporary root fd: %w", err)
	}

	if !settings.Network {
		if err := setupLoopbackInterface(); err != nil {
			return fmt.Errorf("failed to setup lookpback interface: %w", err)
		}

		if len(settings.AllowedHosts) > 0 {
			// add a dummy network interface
			// otherwise Chromium sets Navigator.onLine to false even though we have a working proxy
			if err := addDummyInterface(); err != nil {
				return fmt.Errorf("failed to setup dummy network interface: %w", err)
			}
		}
	}

	// Do not allow creating a new user namespace. After dropping capabilties this can't changed anymore.
	// This in necessary for seccomp=="no" but do it in any case for extra safety.
	if err := restrictUserNamespaces(); err != nil {
		return fmt.Errorf("unable to restrict user namespaces: %w", err)
	}

	if err := dropCapabilityBoundingSet(); err != nil {
		return fmt.Errorf("dropping capability bounding set failed: %w", err)
	}

	if err := dropCapabilities(); err != nil {
		return fmt.Errorf("dropping capabilities failed: %w", err)
	}

	if err := os.Chdir(settings.Cwd); err != nil {
		return fmt.Errorf("chdir to %s failed: %w", settings.Cwd, err)
	}

	if settings.Seccomp != "no" {
		seccompFilters, err := loadSeccomp(settings.Seccomp, settings.Debug)
		if err != nil {
			return err
		}
		defer func() {
			for _, filter := range seccompFilters {
				filter.Release()
			}
		}()

		for _, filter := range seccompFilters {
			if err := filter.Load(); err != nil {
				return err
			}
		}
	} else {
		if _, err := unix.Setsid(); err != nil {
			return err
		}
	}

	helperPids := []int{}

	for _, helper := range settings.Helpers {
		executable, err := exec.LookPath(helper[0])
		if err != nil {
			return fmt.Errorf("helper executable does not exist: %w", err)
		}

		args := make([]string, len(helper))
		copy(args, helper)
		if args[0] == "/proc/self/exe" {
			args[0] = os.Args[0]
		}

		cmd := exec.Cmd{
			Path:   executable,
			Args:   args,
			Stdin:  os.Stdin,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
			Env:    os.Environ(),
		}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("running helper failed: %w", err)
		}
		helperPids = append(helperPids, cmd.Process.Pid)
	}

	executable, err := exec.LookPath(settings.Command[0])
	if err != nil {
		return fmt.Errorf("executable does not exist: %w", err)
	}

	if len(settings.OverrideArg0) > 0 {
		settings.Command[0] = settings.OverrideArg0
	}

	cmd := exec.Cmd{
		Path:   executable,
		Args:   settings.Command,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Env:    os.Environ(),
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("running command failed: %w", err)
	}

	var syncFile *os.File
	if passStruct.ReturnCodeFd != -1 {
		syncFile = os.NewFile(uintptr(passStruct.ReturnCodeFd), "pipe")
	}

	return reapChildren(cmd.Process.Pid, helperPids, syncFile)
}
