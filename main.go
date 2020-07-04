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
	"sort"
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

	mounts := mergeMounts(defaultMountOptions, configMountOptions)
	mounts = mergeMounts(mounts, flagMountOptions)
	if err := validateMounts(mounts); err != nil {
		fatalErr(err)
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Path < mounts[j].Path })

	fmt.Printf("%v\n", mounts)

	if settings.SandboxBackend == "userns" {
		err = usernsRun(settings, mounts)
	} else {
		err = bwrapRun(settings, mounts)
	}

	if err != nil {
		fatalErr(err)
	}
}
