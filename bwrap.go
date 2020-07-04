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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

func bwrapRun(settings settingsStruct, mounts []mount) error {
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
			bwrapArgs = append(bwrapArgs, "--ro-bind-data", mount.Other, mount.Path)
		default:
			panic("")
		}
	}

	bwrapArgs = append(bwrapArgs, remountRoArgs...)

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

	execArgs := append([]string{"bwrap"}, "--args", strconv.Itoa(int(bwrapArgsDataFile.Fd())), "--")
	execArgs = append(execArgs, settings.Command...)

	return syscall.Exec(cmdPath, execArgs, os.Environ())
}
