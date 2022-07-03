// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) 2020-2022 Felix Geyer <debfx@fobos.de>

package main

type settingsStruct struct {
	Debug         bool
	Network       bool
	AllowedHosts  []string
	Ipc           bool
	Cwd           string
	Seccomp       string
	DbusOwn       []string
	DbusTalk      []string
	DbusCall      []string
	DbusBroadcast []string
	Profiles      []string
	Name          string
	SyncFds       []uintptr
	Command       []string
	OverrideArg0  string
	Helpers       [][]string
	SystemdUnit   bool
}

func getDefaultSettings() settingsStruct {
	return settingsStruct{
		Debug:       false,
		Network:     false,
		Ipc:         false,
		Cwd:         ".",
		Seccomp:     "yes",
		SystemdUnit: true,
	}
}
