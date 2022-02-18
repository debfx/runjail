// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) 2020-2022 Felix Geyer <debfx@fobos.de>

/*
unix_user_* is a fork of parts of the golang os/user code to expose the
user shell in the returned struct.
Additionally Uid and Gid are uint64 instead of strings.
*/

package main

import "syscall"

type unixUser struct {
	Uid      uint64
	Gid      uint64
	Username string
	Name     string
	HomeDir  string
	Shell    string
}

func currentUnixUser() (*unixUser, error) {
	return lookupUnixUid(syscall.Getuid())
}
