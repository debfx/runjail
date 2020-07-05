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
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"

	flag "github.com/spf13/pflag"
)

func expandCmdFlags() []string {
	// pflag doesn't support passing multiple values to slice arguments like this: --slice first second
	// work around this by doing some proprocessing on os.Args
	// this example would be transformed to: --slice first --slice second
	expandedArgs := []string{}
	sliceArgs := map[string]bool{
		"--ro":      true,
		"--rw":      true,
		"--hide":    true,
		"--empty":   true,
		"--bind-ro": true,
		"--bind-rw": true,
	}
	inSliceArg := false
	firstListArg := true
	lastFlagName := ""
	for index, arg := range os.Args[1:] {
		if arg == "--" {
			// all args after "--" are positional so just copy them and exit the loop
			expandedArgs = append(expandedArgs, os.Args[index+1:]...)
			break
		}

		if strings.HasPrefix(arg, "-") {
			_, inSliceArg = sliceArgs[arg]
			if inSliceArg {
				// remember the current flag name so we can insert it later
				lastFlagName = arg
				// the next argument is the first after the flag so doesn't need changes
				firstListArg = true
			}
		} else if inSliceArg {
			if firstListArg {
				firstListArg = false
			} else {
				expandedArgs = append(expandedArgs, lastFlagName)
			}
		}

		expandedArgs = append(expandedArgs, arg)
	}

	return expandedArgs
}

func setupDbusProxy(originalSettings settingsStruct) (proxyPipe uintptr, dbusMount mount, cleanupFile string, err error) {
	runtimeDir, err := getUserRuntimeDir()
	if err != nil {
		return
	}

	proxySocketDir := path.Join(runtimeDir, ".dbus-proxy")
	if err = os.MkdirAll(proxySocketDir, 0750); err != nil {
		return
	}
	proxySocketFile, err := ioutil.TempFile(proxySocketDir, "session-bus-proxy-")
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

	printCmdArgs := strings.Join(dbusProxyArgs, " ")
	fmt.Fprintf(os.Stderr, "Running: dbus-proxy %s\n", printCmdArgs)

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
	settings.SandboxBackend = originalSettings.SandboxBackend

	err = run(settings, mountOptions, os.Environ(), true)
	if err != nil {
		return
	}

	dataRead := make([]byte, 1)
	bytesRead, err := pipeR.Read(dataRead)
	if err != nil {
		return
	}
	if bytesRead != 1 {
		err = fmt.Errorf("failed to initalize dbus proxy, syncing failed")
		return
	}

	proxyPipe = pipeR.Fd()
	dbusMount = mount{Type: mountTypeBindRw, Path: hostSocketPath, Other: proxySocketFile.Name()}
	return
}

func main() {
	var err error

	// internal subcommand
	if len(os.Args) > 1 && os.Args[1] == "userns-child" {
		fatalErr(usernsChild())
	}

	flagRo := flag.StringSlice("ro", []string{}, "Mount file/directory from parent namespace read-only.")
	flagRw := flag.StringSlice("rw", []string{}, "Mount file/directory from parent namespace read-write.")
	flagHide := flag.StringSlice("hide", []string{}, "Make file/directory inaccessible.")
	flagEmpty := flag.StringSlice("empty", []string{}, "Mount empty tmpfs on the specified path.")
	flagBindRo := flag.StringSlice("bind-ro", []string{}, "Bind mount source file/directory from parent namespace to target read-only (Format: \"source:target\").")
	flagBindRw := flag.StringSlice("bind-rw", []string{}, "Bind mount source file/directory from parent namespace to target read-write (Format: \"source:target\").")
	flagDebug := flag.Bool("debug", false, "Enable debug mode.")
	flagIpc := flag.Bool("ipc", false, "Allow IPC (don't start an own IPC namespace).")
	flagNet := flag.String("net", "no", "Enable/disable network access (yes/no).")
	flagCwd := flag.String("cwd", ".", "Set the current working directory.")
	flagSeccomp := flag.String("seccomp", "yes", "Enable seccomp syscall filtering (yes/minimal/no).")
	flagProfile := flag.StringSlice("profile", []string{}, "Enable predefined profiles (x11/wayland).")
	flagConfig := flag.String("config", "", "Fetch options from config file.")
	flagBackend := flag.String("backend", "userns", "Backend for sandbox (userns/bwrap).")

	expandedArgs := expandCmdFlags()

	// Ignore errors; CommandLine is set for ExitOnError.
	flag.CommandLine.Parse(expandedArgs)

	settings := getDefaultSettings()

	if len(flag.Args()) == 0 {
		userShell, err := getUserShell()
		if err != nil {
			fatalErr(err)
		}
		settings.Command = []string{userShell}
	} else {
		settings.Command = flag.Args()
	}

	defaultRawMountOptions, err := getDefaultOptions()
	if err != nil {
		fatalErr(err)
	}
	defaultMountOptions, err := parseRawMountOptions(defaultRawMountOptions)
	if err != nil {
		fatalErr(err)
	}

	var configMountOptions []mount
	if flag.Lookup("config").Changed {
		config, err := parseConfig(*flagConfig)
		if err != nil {
			fatalErr(err)
		}

		configRawMountOptions := rawMountOptions{
			Ro:     config.Ro,
			Rw:     config.Rw,
			Hide:   config.Hide,
			Empty:  config.Empty,
			BindRo: config.BindRo,
			BindRw: config.BindRw,
		}
		configMountOptions, err = parseRawMountOptions(configRawMountOptions)
		if err != nil {
			fatalErr(err)
		}

		if config.Ipc != nil {
			settings.Ipc = *config.Ipc
		}
		if config.Cwd != "" {
			settings.Cwd = config.Cwd
		}
		if config.Seccomp != "" {
			settings.Seccomp = config.Seccomp
		}
		if len(config.Profiles) != 0 {
			settings.Profiles = config.Profiles
		}
		if len(config.Command) != 0 {
			settings.Command = config.Command
		}
		if config.Backend != "" {
			settings.SandboxBackend = config.Backend
		}
	}

	if flag.Lookup("debug").Changed {
		settings.Debug = *flagDebug
	}
	if flag.Lookup("ipc").Changed {
		settings.Ipc = *flagIpc
	}
	if flag.Lookup("net").Changed {
		settings.Network, err = yesNoStrToBool(*flagNet)
		if err != nil {
			fatalErr(err)
		}
	}
	if flag.Lookup("cwd").Changed {
		settings.Cwd, err = preprocessPath(*flagCwd, false)
		if err != nil {
			fatalErr(err)
		}
	}
	if flag.Lookup("seccomp").Changed {
		settings.Seccomp = *flagSeccomp
	}

	if settings.Seccomp != "yes" && settings.Seccomp != "minimal" && settings.Seccomp != "no" {
		fatal(fmt.Sprintf("\"%s\" ist not a valid value for seccomp", settings.Seccomp))
	}

	if flag.Lookup("profile").Changed {
		for _, profileArg := range *flagProfile {
			settings.Profiles = append(settings.Profiles, strings.Split(profileArg, ",")...)
		}
	}

	if flag.Lookup("backend").Changed {
		settings.SandboxBackend = *flagBackend
	}
	if settings.SandboxBackend != "userns" && settings.SandboxBackend != "bwrap" {
		fatal(fmt.Sprintf("\"%s\" is not a valid sandbox backend", settings.SandboxBackend))
	}

	if len(flag.Args()) != 0 {
		settings.Command = flag.Args()
	}

	flagRawMountOptions := rawMountOptions{
		Ro:    *flagRo,
		Rw:    *flagRw,
		Hide:  *flagHide,
		Empty: *flagEmpty,
	}

	flagRawMountOptions.BindRo, err = splitMapOption(*flagBindRo)
	if err != nil {
		fatalErr(err)
	}

	flagRawMountOptions.BindRw, err = splitMapOption(*flagBindRw)
	if err != nil {
		fatalErr(err)
	}

	flagMountOptions, err := parseRawMountOptions(flagRawMountOptions)
	if err != nil {
		fatalErr(err)
	}

	mounts := defaultMountOptions
	envVars := map[string]string{}
	for _, item := range os.Environ() {
		splits := strings.SplitN(item, "=", 2)
		envVars[splits[0]] = splits[1]
	}
	for _, profileName := range settings.Profiles {
		profile, err := getProfile(profileName)
		if err != nil {
			fatalErr(err)
		}

		mounts = mergeMounts(mounts, profile.Mounts)
		for key, value := range profile.EnvVars {
			envVars[key] = value
		}

		// merge a subset of settings
		settings.DbusOwn = append(settings.DbusOwn, profile.Settings.DbusOwn...)
		settings.DbusTalk = append(settings.DbusTalk, profile.Settings.DbusTalk...)
		settings.DbusCall = append(settings.DbusCall, profile.Settings.DbusCall...)
		settings.DbusBroadcast = append(settings.DbusBroadcast, profile.Settings.DbusBroadcast...)
	}

	mounts = mergeMounts(mounts, configMountOptions)
	mounts = mergeMounts(mounts, flagMountOptions)

	if len(settings.DbusOwn) > 0 || len(settings.DbusTalk) > 0 || len(settings.DbusCall) > 0 || len(settings.DbusBroadcast) > 0 {
		pipe, dbusMount, cleanupFile, err := setupDbusProxy(settings)
		if len(cleanupFile) > 0 {
			defer func() {
				if err := os.Remove(cleanupFile); err != nil {
					fmt.Printf("Failed to remove temp file %s: %v\n", cleanupFile, err)
				}
			}()
		}
		if err != nil {
			fatalErr(err)
		}
		settings.SyncFds = append(settings.SyncFds, pipe)
		mounts = mergeMounts(mounts, []mount{dbusMount})
	}

	envVarsFlat := []string{}
	for key, value := range envVars {
		envVarsFlat = append(envVarsFlat, key+"="+value)
	}

	err = run(settings, mounts, envVarsFlat, false)
	if err != nil {
		fatalErr(err)
	}
}

func run(settings settingsStruct, mounts []mount, environ []string, fork bool) error {
	if err := validateMounts(mounts); err != nil {
		fatalErr(err)
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Path < mounts[j].Path })

	fmt.Printf("%v\n", mounts)

	if settings.SandboxBackend == "userns" {
		return usernsRun(settings, mounts, environ, fork)
	} else {
		return bwrapRun(settings, mounts, environ, fork)
	}
}
