// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.BSD file.

// +build aix darwin dragonfly freebsd js,wasm !android,linux netbsd openbsd solaris
// +build !cgo

package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
)

const groupFile = "/etc/group"
const userFile = "/etc/passwd"

var colon = []byte{':'}

// lineFunc returns a value, an error, or (nil, nil) to skip the row.
type lineFunc func(line []byte) (v interface{}, err error)

// readColonFile parses r as an /etc/group or /etc/passwd style file, running
// fn for each row. readColonFile returns a value, an error, or (nil, nil) if
// the end of the file is reached without a match.
func readColonFile(r io.Reader, fn lineFunc) (v interface{}, err error) {
	bs := bufio.NewScanner(r)
	for bs.Scan() {
		line := bs.Bytes()
		// There's no spec for /etc/passwd or /etc/group, but we try to follow
		// the same rules as the glibc parser, which allows comments and blank
		// space at the beginning of a line.
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		v, err = fn(line)
		if v != nil || err != nil {
			return
		}
	}
	return nil, bs.Err()
}

// returns a *User for a row if that row's has the given value at the
// given index.
func matchUserIndexValue(value string, idx int) lineFunc {
	var leadColon string
	if idx > 0 {
		leadColon = ":"
	}
	substr := []byte(leadColon + value + ":")
	return func(line []byte) (v interface{}, err error) {
		if !bytes.Contains(line, substr) || bytes.Count(line, colon) < 6 {
			return
		}
		// kevin:x:1005:1006::/home/kevin:/usr/bin/zsh
		parts := strings.SplitN(string(line), ":", 7)
		if len(parts) < 6 || parts[idx] != value || parts[0] == "" ||
			parts[0][0] == '+' || parts[0][0] == '-' {
			return
		}
		var uid, gid uint64
		if uid, err = strconv.ParseUint(parts[2], 10, 64); err != nil {
			return nil, nil
		}
		if gid, err = strconv.ParseUint(parts[3], 10, 64); err != nil {
			return nil, nil
		}
		u := &unixUser{
			Username: parts[0],
			Uid:      uid,
			Gid:      gid,
			Name:     parts[4],
			HomeDir:  parts[5],
			Shell:    parts[6],
		}
		// The pw_gecos field isn't quite standardized. Some docs
		// say: "It is expected to be a comma separated list of
		// personal data where the first item is the full name of the
		// user."
		if i := strings.Index(u.Name, ","); i >= 0 {
			u.Name = u.Name[:i]
		}
		return u, nil
	}
}

func findUserId(uid string, r io.Reader) (*unixUser, error) {
	i, e := strconv.Atoi(uid)
	if e != nil {
		return nil, errors.New("user: invalid userid " + uid)
	}
	if v, err := readColonFile(r, matchUserIndexValue(uid, 2)); err != nil {
		return nil, err
	} else if v != nil {
		return v.(*unixUser), nil
	}
	return nil, user.UnknownUserIdError(i)
}

func lookupUnixUid(uid int) (*unixUser, error) {
	f, err := os.Open(userFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return findUserId(strconv.Itoa(uid), f)
}
