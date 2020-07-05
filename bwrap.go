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
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func bwrapRun(settings settingsStruct, mounts []mount, environ []string, fork bool) error {
	bwrapArgs := []string{"--unshare-pid", "--proc", "/proc"}
	remountRoArgs := []string{}

	if !settings.Ipc {
		bwrapArgs = append(bwrapArgs, "--unshare-ipc")
	}

	cwd, err := preprocessPath(settings.Cwd, true)
	if err != nil {
		return err
	}
	bwrapArgs = append(bwrapArgs, "--chdir", cwd)

	for _, mount := range mounts {
		switch mount.Type {
		case mountTypeBindRo:
			bwrapArgs = append(bwrapArgs, "--ro-bind", mount.Other, mount.Path)
		case mountTypeBindRw:
			if strings.HasPrefix(mount.Other, "/dev/") {
				bwrapArgs = append(bwrapArgs, "--dev-bind", mount.Other, mount.Path)
			} else {
				bwrapArgs = append(bwrapArgs, "--bind", mount.Other, mount.Path)
			}
		case mountTypeHide:
			bwrapArgs = append(bwrapArgs, "--tmpfs", mount.Path)
			// move --remount-ro to the end so we can still mount sth in sub-paths
			remountRoArgs = append(remountRoArgs, "--remount-ro", mount.Path)
		case mountTypeEmpty:
			bwrapArgs = append(bwrapArgs, "--tmpfs", mount.Path)
		case mountTypeSymlink:
			bwrapArgs = append(bwrapArgs, "--symlink", mount.Other, mount.Path)
		case mountTypeFileData:
			data, _ := base64.StdEncoding.DecodeString(mount.Other)
			dataFile, err := getDataFileBytes(data)
			if err != nil {
				return err
			}
			defer dataFile.Close()
			bwrapArgs = append(bwrapArgs, "--ro-bind-data", strconv.Itoa(int(dataFile.Fd())), mount.Path)
		default:
			panic("")
		}
	}

	bwrapArgs = append(bwrapArgs, remountRoArgs...)

	for _, fd := range settings.SyncFds {
		bwrapArgs = append(bwrapArgs, "--sync-fd", strconv.Itoa(int(fd)))
		if err := clearCloseOnExec(fd); err != nil {
			return err
		}
	}

	cmdPath, err := exec.LookPath("bwrap")
	if err != nil {
		return err
	}

	if settings.Debug {
		printArgs := strings.Join(bwrapArgs, " ")
		printCmdArgs := strings.Join(settings.Command, " ")
		fmt.Fprintf(os.Stderr, "Running: bwrap %s -- %s\n", printArgs, printCmdArgs)
	}

	bwrapArgsDataFile, err := getDataFile(strings.Join(bwrapArgs, "\x00") + "\x00")
	if err != nil {
		return err
	}
	defer bwrapArgsDataFile.Close()

	execArgs := append([]string{"bwrap"}, "--args", strconv.Itoa(int(bwrapArgsDataFile.Fd())), "--")
	execArgs = append(execArgs, settings.Command...)

	if fork {
		cmd := exec.Cmd{
			Path:   cmdPath,
			Args:   execArgs,
			Stdin:  os.Stdin,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
			Env:    environ,
		}
		if err := cmd.Start(); err != nil {
			return err
		}

		return nil
	} else {
		return syscall.Exec(cmdPath, execArgs, environ)
	}
}
