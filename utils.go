// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) Felix Geyer <debfx@fobos.de>

package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	SendfileMaxSize = 0x7FFFF000
)

func getUsername() (string, error) {
	user, err := user.Current()
	if err != nil {
		return "", err
	}
	return user.Username, nil
}

func getUserHomeDir() (string, error) {
	if env := os.Getenv("HOME"); env != "" {
		return env, nil
	}

	user, err := user.Current()
	if err != nil {
		return "", err
	}
	return user.HomeDir, nil
}

func getUserRuntimeDir() (string, error) {
	if env := os.Getenv("XDG_RUNTIME_DIR"); env != "" {
		return env, nil
	}

	user, err := user.Current()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("/run/user/%s", user.Uid), nil
}

func getUserShell() (string, error) {
	if env := os.Getenv("SHELL"); env != "" {
		return env, nil
	}

	user, err := currentUnixUser()
	if err != nil {
		return "", err
	}
	return user.Shell, nil
}

func isStringInSlice(val string, list []string) bool {
	for _, elem := range list {
		if elem == val {
			return true
		}
	}

	return false
}

func isIntInSlice(val int, list []int) bool {
	for _, elem := range list {
		if elem == val {
			return true
		}
	}

	return false
}

// Returns a slice that has first occournces of `val` removed from `list`
// Warning: does not preserve order of elements in `list`
func removeIntFromSlice(val int, list []int) []int {
	for i, elem := range list {
		if elem == val {
			list[i] = list[len(list)-1]
			return list[:len(list)-1]
		}
	}

	return list
}

func splitMapOption(args []string) (map[string]string, error) {
	result := map[string]string{}

	for _, arg := range args {
		split := strings.Split(arg, ":")
		if len(split) != 2 || len(split[0]) == 0 || len(split[1]) == 0 {
			return nil, fmt.Errorf("invalid format: \"%s\", needs to be \"x:y\"", arg)
		}

		result[split[0]] = split[1]
	}

	return result, nil
}

func fatal(str string) {
	fmt.Fprintf(os.Stderr, "%s\n", str)
	os.Exit(1)
}

func fatalErr(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err.Error())
	os.Exit(1)
}

func yesNoStrToBool(str string) (bool, error) {
	switch strings.ToLower(str) {
	case "yes", "y", "true", "t", "1":
		return true, nil
	case "no", "n", "false", "f", "0":
		return false, nil
	}

	return false, fmt.Errorf("\"%s\" is not a valid yes/no value", str)
}

func setCloseOnExec(fd uintptr) error {
	flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
	if err != nil {
		return err
	}

	_, err = unix.FcntlInt(fd, unix.F_SETFD, flags|unix.FD_CLOEXEC)
	if err != nil {
		return err
	}

	return nil
}

func clearCloseOnExec(fd uintptr) error {
	flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
	if err != nil {
		return err
	}

	_, err = unix.FcntlInt(fd, unix.F_SETFD, flags & ^unix.FD_CLOEXEC)
	if err != nil {
		return err
	}

	return nil
}

func setFdReadOnly(fd uintptr) error {
	_, err := unix.FcntlInt(fd, unix.F_SETFL, unix.O_RDONLY)
	if err != nil {
		return err
	}
	return nil
}

func getDataFileBytes(bytes []byte) (*os.File, error) {
	tmpfile, err := createTempFile("")
	if err != nil {
		return nil, err
	}

	if len(bytes) != 0 {
		if _, err := tmpfile.Write(bytes); err != nil {
			return nil, err
		}

		// seek to beginning since the fd is read() later
		if _, err := tmpfile.Seek(0, 0); err != nil {
			return nil, err
		}
	}

	if err := clearCloseOnExec(tmpfile.Fd()); err != nil {
		return nil, err
	}
	if err := setFdReadOnly(tmpfile.Fd()); err != nil {
		return nil, err
	}

	return tmpfile, nil
}

func createTempFile(dir string) (*os.File, error) {
	if dir == "" {
		dir = os.TempDir()
	}

	fd, err := unix.Open(dir, unix.O_RDWR|unix.O_TMPFILE|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, &os.PathError{
			Op:   "open",
			Path: dir,
			Err:  err,
		}
	}

	path := "/proc/self/fd/" + strconv.Itoa(fd)
	return os.NewFile(uintptr(fd), path), nil
}

func getAllRunningPids() ([]int, error) {
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc: %w", err)
	}
	defer procDir.Close()

	result := []int{}

	dirNames, err := procDir.Readdirnames(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc entries: %w", err)
	}

	for _, name := range dirNames {
		pid, err := strconv.ParseInt(name, 10, 0)
		if err != nil {
			continue
		}

		result = append(result, int(pid))
	}

	return result, nil
}

// isTerminal return true if the file descriptor is terminal.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

// terminalName prints the file name of the terminal connected to the fd
func terminalName(fd uintptr) (string, error) {
	dest, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "", err
	}
	return dest, nil
}

func clonePathAsMemfd(path string, memfdName string) (int, error) {
	// newer kernel print a warning on memfd_create() without MFD_EXEC or MFD_NOEXEC_SEAL
	memFd, err := unix.MemfdCreate(memfdName, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if errors.Is(err, unix.EINVAL) {
		// older kernels don't support MFD_EXEC, try without it
		memFd, err = unix.MemfdCreate(memfdName, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	}
	if err != nil {
		return 0, err
	}
	defer unix.Close(memFd)

	sourceFd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(sourceFd)

	_, err = unix.Sendfile(memFd, sourceFd, nil, SendfileMaxSize)
	if err != nil {
		return 0, err
	}

	_, err = unix.FcntlInt(uintptr(memFd), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE)
	if err != nil {
		return 0, err
	}

	// re-open memFd read-only
	newFd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", memFd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}

	return newFd, nil
}

func getOpenFiles() ([]int, error) {
	procDir, err := os.Open("/proc/self/fd")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/self/fd/: %w", err)
	}
	defer procDir.Close()

	result := []int{}

	entries, err := procDir.Readdir(0)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fdNum, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		result = append(result, fdNum)
	}

	return result, nil
}

func closeOnExecAllOpenFds() error {
	openFds, err := getOpenFiles()
	if err != nil {
		return fmt.Errorf("failed to get open fds: %w", err)
	}
	for _, openFd := range openFds {
		if openFd <= 2 {
			continue
		}

		err = setCloseOnExec(uintptr(openFd))
		// ignore EBADF in case the fd has been closed in the meantime
		if err != nil && !errors.Is(err, unix.EBADF) {
			return fmt.Errorf("failed to set O_CLOEXEC on fd %d: %w", openFd, err)
		}
	}

	return nil
}
