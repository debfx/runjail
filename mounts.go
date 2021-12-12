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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
)

type rawMountOptions struct {
	Ro        []string
	RoTry     []string
	Rw        []string
	RwTry     []string
	Empty     []string
	Hide      []string
	HideTry   []string
	BindRo    map[string]string
	BindRoTry map[string]string
	BindRw    map[string]string
	BindRwTry map[string]string
	Symlink   map[string]string
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
	Path     string
	Type     int
	Other    string
	Optional bool
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
	defaults.Rw = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"}
	defaults.BindRw = make(map[string]string)
	defaults.Empty = []string{"/tmp", "/var/tmp", "/dev/shm", userHomeDir, userRuntimeDir}
	defaults.Symlink = make(map[string]string)
	defaults.Symlink["/dev/fd"] = "/proc/self/fd"
	defaults.Symlink["/dev/stdin"] = "/proc/self/fd/0"
	defaults.Symlink["/dev/stdout"] = "/proc/self/fd/1"
	defaults.Symlink["/dev/stderr"] = "/proc/self/fd/2"
	defaults.Symlink["/dev/ptmx"] = "/dev/pts/ptmx"
	defaults.HideTry = []string{
		"/proc/asound",
		"/proc/acpi",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/sys/firmware",
	}

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

	if isTerminal(1) {
		ttyPath, err := terminalName(1)
		if err != nil {
			return rawMountOptions{}, fmt.Errorf("reading the tty name failed: %w", err)
		}
		defaults.BindRw[ttyPath] = "/dev/console"
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

func parseRawMountBind(path string, other string, readonly bool, optional bool) (mount, error) {
	pathProcessed, err := preprocessPath(path, false)
	if err != nil {
		return mount{}, err
	}
	otherProcessed, err := preprocessPath(other, true)
	if err != nil {
		return mount{}, err
	}

	mount := mount{Path: pathProcessed, Other: otherProcessed, Optional: optional}
	if readonly {
		mount.Type = mountTypeBindRo
	} else {
		mount.Type = mountTypeBindRw
	}
	return mount, nil
}

func parseRawMountOptions(options rawMountOptions) ([]mount, error) {
	mounts := []mount{}

	for _, path := range options.Ro {
		mount, err := parseRawMountBind(path, path, true, false)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
	}

	for _, path := range options.RoTry {
		mount, err := parseRawMountBind(path, path, true, true)
		if err == nil {
			mounts = append(mounts, mount)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	for _, path := range options.Rw {
		mount, err := parseRawMountBind(path, path, false, false)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
	}

	for _, path := range options.RwTry {
		mount, err := parseRawMountBind(path, path, false, true)
		if err == nil {
			mounts = append(mounts, mount)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	for _, path := range options.Hide {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Type: mountTypeHide}
		mounts = append(mounts, mount)
	}

	for _, path := range options.HideTry {
		pathProcessed, err := preprocessPath(path, false)
		if err != nil {
			return nil, err
		}

		mount := mount{Path: pathProcessed, Type: mountTypeHide, Optional: true}
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
		mount, err := parseRawMountBind(path, source, true, false)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
	}

	for source, path := range options.BindRoTry {
		mount, err := parseRawMountBind(path, source, true, true)
		if err == nil {
			mounts = append(mounts, mount)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	for source, path := range options.BindRw {
		mount, err := parseRawMountBind(path, source, false, false)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
	}

	for source, path := range options.BindRwTry {
		mount, err := parseRawMountBind(path, source, false, true)
		if err == nil {
			mounts = append(mounts, mount)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
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

func removeLastPathPart(path string) string {
	index := strings.LastIndex(path, "/")
	if index == -1 {
		return path
	}
	if index == 0 {
		return "/"
	}
	return path[:index]
}

func mergeMounts(low []mount, high []mount, debug bool) []mount {
	highMountTargets := []string{}
	lowMountTargets := []string{}
	mountResult := []mount{}

	for _, mount := range high {
		if isStringInSlice(mount.Path, highMountTargets) {
			// this mountpoint already exists from the same source, error
			panic(mount.Path)
		}

		mountResult = append(mountResult, mount)
		highMountTargets = append(highMountTargets, mount.Path)
	}

	for _, mount := range low {
		path := mount.Path
		// skip if this or a parent path is present in a `high` mount
		skipMount := false
		for path != "/" {
			if isStringInSlice(path, highMountTargets) {
				if debug {
					fmt.Printf("Skipping mount \"%s\", superseded by mount \"%s\"\n", mount.Path, path)
				}
				skipMount = true
				break
			}
			path = removeLastPathPart(path)
		}
		if skipMount {
			continue
		}
		if isStringInSlice(mount.Path, lowMountTargets) {
			// this mountpoint already exists from the same source, error
			panic(mount.Path)
		}

		mountResult = append(mountResult, mount)
		lowMountTargets = append(lowMountTargets, mount.Path)
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
