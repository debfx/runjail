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
	"path"
	"path/filepath"
	"strings"
)

type rawMountOptions struct {
	Ro      []string
	Rw      []string
	Empty   []string
	Hide    []string
	BindRo  map[string]string
	BindRw  map[string]string
	Symlink map[string]string
}

const (
	mountTypeBindRo = iota
	mountTypeBindRw
	mountTypeHide
	mountTypeEmpty
	mountTypeSymlink
	mountTypeFileData
)

type mount struct {
	Path  string
	Type  int
	Other string
}

func getDefaultOptions() (rawMountOptions, error) {
	userHomeDir, err := getUserHomeDir()
	if err != nil {
		return rawMountOptions{}, err
	}

	userRuntimeDir, err := getUserRuntimeDir()
	if err != nil {
		return rawMountOptions{}, err
	}

	defaults := rawMountOptions{}

	defaults.Ro = []string{}
	defaults.Rw = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/pts", "/dev/ptmx"}
	defaults.Empty = []string{"/tmp", "/var/tmp", "/dev/shm", userHomeDir, userRuntimeDir}
	defaults.Symlink = make(map[string]string)
	defaults.Symlink["/dev/fd"] = "/proc/self"
	defaults.Symlink["/dev/stdin"] = "/proc/self/fd/0"
	defaults.Symlink["/dev/stdout"] = "/proc/self/fd/1"
	defaults.Symlink["/dev/stderr"] = "/proc/self/fd/2"

	files, err := ioutil.ReadDir("/")
	if err != nil {
		return rawMountOptions{}, err
	}
	for _, file := range files {
		absolutePath := path.Join("/", file.Name())
		if isStringInSlice(file.Name(), []string{"bin", "sbin"}) || strings.HasPrefix(file.Name(), "lib") {
			if file.Mode()&os.ModeSymlink != 0 {
				symlinkTarget, err := filepath.EvalSymlinks(absolutePath)
				if err != nil {
					return rawMountOptions{}, err
				}
				defaults.Symlink[absolutePath] = symlinkTarget
			} else {
				defaults.Ro = append(defaults.Ro, absolutePath)
			}
		} else if isStringInSlice(file.Name(), []string{"etc", "selinux", "sys", "usr", "var"}) {
			// ideally we'd mount a new sysfs but the kernel only allows this if we are admin of the network namespace
			defaults.Ro = append(defaults.Ro, absolutePath)
		}
	}

	return defaults, nil
}

func pathExpandUser(path string) (string, error) {
	if path[:1] != "~" {
		return path, nil
	}

	index := strings.Index(path, "/")
	if index == -1 {
		index = len(path)
	}

	var userHome string

	if index == 1 {
		var err error
		userHome, err = getUserHomeDir()
		if err != nil {
			return "", err
		}
	} else {
		username := path[1:index]
		user, err := user.Lookup(username)
		if err != nil {
			// user doesn't exist / lookup error -> return path unchanged
			return path, nil
		}
		userHome = user.HomeDir
	}

	userHome = strings.TrimRight(userHome, "/")

	return userHome + path[index:], nil
}

func preprocessPath(path string, evalSymlinks bool) (string, error) {
	var result string
	var err error

	path, err = pathExpandUser(path)
	if err != nil {
		return "", err
	}

	if evalSymlinks {
		path, err = filepath.EvalSymlinks(path)
		if err != nil {
			return "", err
		}
	}

	result, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}

	return result, nil
}

func parseRawMountOptions(options rawMountOptions) ([]mount, error) {
	mounts := []mount{}

	for _, path := range options.Ro {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}
		otherProcessed, err := preprocessPath(path, true)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Other: otherProcessed, Type: mountTypeBindRo}
		mounts = append(mounts, mount)
	}

	for _, path := range options.Rw {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}
		otherProcessed, err := preprocessPath(path, true)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Other: otherProcessed, Type: mountTypeBindRw}
		mounts = append(mounts, mount)
	}

	for _, path := range options.Hide {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Type: mountTypeHide}
		mounts = append(mounts, mount)
	}

	for _, path := range options.Empty {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Type: mountTypeEmpty}
		mounts = append(mounts, mount)
	}

	for source, path := range options.BindRo {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}
		otherProcessed, err := preprocessPath(source, true)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Other: otherProcessed, Type: mountTypeBindRo}
		mounts = append(mounts, mount)
	}

	for source, path := range options.BindRw {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}
		otherProcessed, err := preprocessPath(source, true)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Other: otherProcessed, Type: mountTypeBindRw}
		mounts = append(mounts, mount)
	}

	for path, target := range options.Symlink {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}
		otherProcessed, err := preprocessPath(target, false)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Other: otherProcessed, Type: mountTypeSymlink}
		mounts = append(mounts, mount)
	}

	return mounts, nil
}

func mergeMounts(low []mount, high []mount) []mount {
	flagMountTargets := []string{}
	previousMountTargets := []string{}

	mountResult := []mount{}

	for _, mount := range high {
		if isStringInSlice(mount.Path, flagMountTargets) {
			// this mountpoint already exists from the same source, error
			panic(mount.Path)
		}

		mountResult = append(mountResult, mount)
		flagMountTargets = append(flagMountTargets, mount.Path)
	}

	previousMountTargets = append(previousMountTargets, flagMountTargets...)

	for _, mount := range low {
		if isStringInSlice(mount.Path, previousMountTargets) {
			// this mountpoint already exists from a higher priority source, skip
			continue
		}
		if isStringInSlice(mount.Path, flagMountTargets) {
			// this mountpoint already exists from the same source, error
			panic(mount.Path)
		}

		mountResult = append(mountResult, mount)
		flagMountTargets = append(flagMountTargets, mount.Path)
	}

	return mountResult
}

func validateMounts(mounts []mount) error {
	hideMounts := []string{}
	symlinkMounts := []string{}

	for _, mount := range mounts {
		if mount.Type == mountTypeHide {
			hideMounts = append(hideMounts, mount.Path)
		} else if mount.Type == mountTypeSymlink {
			symlinkMounts = append(symlinkMounts, mount.Path)
		}
	}

	for _, mount := range mounts {
		if mount.Type == mountTypeBindRo || mount.Type == mountTypeBindRw || mount.Type == mountTypeEmpty {
			for _, pathCheck := range hideMounts {
				if strings.HasPrefix(mount.Path, pathCheck+"/") {
					return fmt.Errorf("can't mount \"%s\" since it's beneath hidden mountpoint \"%s\"", mount.Path, pathCheck)
				}
			}

			for _, pathCheck := range symlinkMounts {
				if strings.HasPrefix(mount.Path, pathCheck+"/") {
					return fmt.Errorf("can't mount \"%s\" since it's beneath symlink \"%s\"", mount.Path, pathCheck)
				}
			}
		}
	}

	return nil
}
