// Copyright (C) 2020 Felix Geyer <debfx@fobos.de>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 or (at your option)
// version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

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
	flags, err := unix.FcntlInt(fd, syscall.F_GETFD, 0)
	if err != nil {
		return err
	}

	_, err = unix.FcntlInt(fd, syscall.F_SETFD, flags|syscall.FD_CLOEXEC)
	if err != nil {
		return err
	}

	return nil
}

func clearCloseOnExec(fd uintptr) error {
	flags, err := unix.FcntlInt(fd, syscall.F_GETFD, 0)
	if err != nil {
		return err
	}

	_, err = unix.FcntlInt(fd, syscall.F_SETFD, flags & ^syscall.FD_CLOEXEC)
	if err != nil {
		return err
	}

	return nil
}

func setFdReadOnly(fd uintptr) error {
	_, err := unix.FcntlInt(fd, syscall.F_SETFL, syscall.O_RDONLY)
	if err != nil {
		return err
	}
	return nil
}

func getDataFile(str string) (*os.File, error) {
	return getDataFileBytes([]byte(str))
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

func readStringFromFile(path string) (string, error) {
	result, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func readStringFromFileObject(file *os.File) (string, error) {
	result, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(result), nil
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
