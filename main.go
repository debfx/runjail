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
	"sort"
	"strings"

	flag "github.com/spf13/pflag"
)

var selfMemFd int

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

func main() {
	var err error

	// internal subcommands
	if len(os.Args) > 2 {
		if os.Args[1] == "userns-child" {
			err := usernsChild()
			if err != nil {
				fatalErr(err)
			}
			os.Exit(0)
		} else if os.Args[1] == "http-proxy" {
			err = runHttpProxy()
			if err != nil {
				fatalErr(err)
			}
			return
		}
	}
	if len(os.Args) > 1 {
		if os.Args[1] == "http-proxy-forwarder" {
			err = runHttpProxyForwarder()
			if err != nil {
				fatalErr(err)
			}
			return
		}
	}

	if os.Getuid() == 0 {
		fmt.Println("runjail only supports being run by an unprivileged users")
		os.Exit(1)
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
	flagProfile := flag.StringSlice("profile", []string{}, "Enable predefined profiles (x11/wayland/flatpak).")
	flagConfig := flag.String("config", "", "Fetch options from config file.")

	expandedArgs := expandCmdFlags()

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [--flag [--flag ...]] -- [command [command ...]]:\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Ignore errors; CommandLine is set for ExitOnError.
	flag.CommandLine.Parse(expandedArgs) //nolint:golint,errcheck

	selfMemFd, err = clonePathAsMemfd("/proc/self/exe", "runjail")
	if err != nil {
		panic(err)
	}

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
			if pathErr, ok := err.(*os.PathError); ok && os.IsNotExist(err) {
				fatal(fmt.Sprintf("the specified path in the config does not exist: %s", pathErr.Path))
			}
			fatalErr(err)
		}

		if config.Ipc != nil {
			settings.Ipc = *config.Ipc
		}
		if config.Network != "" {
			settings.Network, err = yesNoStrToBool(config.Network)
			if err != nil {
				fatalErr(err)
			}
		}
		if len(config.AllowedHosts) != 0 {
			settings.AllowedHosts = config.AllowedHosts
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
		if config.FlatpakName != "" {
			settings.FlatpakName = config.FlatpakName
		}
		if len(config.Command) != 0 {
			settings.Command = config.Command
		}

		settings.DbusOwn = append(settings.DbusOwn, config.DbusOwn...)
		settings.DbusTalk = append(settings.DbusTalk, config.DbusTalk...)
		settings.DbusCall = append(settings.DbusCall, config.DbusCall...)
		settings.DbusBroadcast = append(settings.DbusBroadcast, config.DbusBroadcast...)
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
		settings.Cwd = *flagCwd
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

	if len(flag.Args()) != 0 {
		settings.Command = flag.Args()
	}

	settings.Command[0], err = exec.LookPath(settings.Command[0])
	if err != nil {
		fatalErr(fmt.Errorf("executable does not exist: %w", err))
	}
	settings.Command[0], err = preprocessPath(settings.Command[0], true)
	if err != nil {
		fatalErr(err)
	}

	settings.Cwd, err = preprocessPath(settings.Cwd, false)
	if err != nil {
		fatalErr(err)
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
		if pathErr, ok := err.(*os.PathError); ok && os.IsNotExist(err) {
			fatal(fmt.Sprintf("the specified path on the command line does not exist: %s", pathErr.Path))
		}
		fatalErr(err)
	}

	mounts := defaultMountOptions
	envVars := map[string]string{}
	for _, item := range os.Environ() {
		splits := strings.SplitN(item, "=", 2)
		envVars[splits[0]] = splits[1]
	}
	for _, profileName := range settings.Profiles {
		profile, err := getProfile(profileName, settings)
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

	if len(settings.AllowedHosts) > 0 {
		err = validateAllowedHosts(settings)
		if err != nil {
			fatalErr(err)
		}

		pipe, proxyMount, cleanupFile, err := setupHttpProxy(settings)
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
		settings.Helpers = append(settings.Helpers, []string{"/proc/self/exe", "http-proxy-forwarder"})
		mounts = mergeMounts(mounts, []mount{proxyMount})
		envVars["http_proxy"] = "http://localhost:18080/"
		envVars["https_proxy"] = "http://localhost:18080/"
	}

	envVarsFlat := []string{}
	for key, value := range envVars {
		envVarsFlat = append(envVarsFlat, key+"="+value)
	}

	exitCode, err := run(settings, mounts, envVarsFlat, false)
	if err != nil {
		fatalErr(err)
	}

	os.Exit(exitCode)
}

func run(settings settingsStruct, mounts []mount, environ []string, fork bool) (int, error) {
	if err := validateMounts(mounts); err != nil {
		fatalErr(err)
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Path < mounts[j].Path })

	return usernsRun(fmt.Sprintf("/proc/self/fd/%d", selfMemFd), settings, mounts, environ, fork)
}
