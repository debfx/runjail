// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) Felix Geyer <debfx@fobos.de>

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/psx"
)

// Use go-landlock once it supports API 6: https://github.com/landlock-lsm/go-landlock/issues/35
// Applying a separate landlock domain per thread is okay for us
// since we only restrict access to abstract unix sockets.

type RulesetAttr struct {
	HandledAccessFS  uint64
	HandledAccessNet uint64
	Scoped           uint64
}

const rulesetAttrSize = 24

func LandlockGetAbi() (int, error) {
	version, _, err := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		unix.LANDLOCK_CREATE_RULESET_VERSION,
	)
	if err != 0 {
		return 0, err
	}

	return int(version), nil
}

func LandLockCreateRuleset(attr *RulesetAttr, flags int) (int, error) {
	fd, _, err := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(attr)),
		uintptr(rulesetAttrSize),
		uintptr(flags),
	)
	if err != 0 {
		return 0, err
	}

	return int(fd), nil
}

func AllThreadsLandlockRestrictSelf(rulesetFd int, flags int) error {
	_, _, err := psx.Syscall3(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFd),
		uintptr(flags),
		0,
	)
	if err != 0 {
		return err
	}

	return nil
}

func landlockIsolateAbstractUnixSocket(debug bool) error {
	abi, err := LandlockGetAbi()
	if err != nil {
		return fmt.Errorf("failed to get landlock ABI: %w", err)
	}

	if abi < 6 {
		if debug {
			fmt.Printf(
				"Kernel only supports Landlock ABI %d, "+
					"but >= 6 is required to restrict access to abstract unix sockets\n",
				abi,
			)
		}
		return nil
	}

	ruleset := RulesetAttr{
		Scoped: unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
	}
	fd, err := LandLockCreateRuleset(&ruleset, 0)
	if err != nil {
		return fmt.Errorf("failed to create landlock ruleset: %w", err)
	}
	defer unix.Close(fd)

	err = AllThreadsLandlockRestrictSelf(fd, 0)
	if err != nil {
		return fmt.Errorf("failed to apply landlock ruleset: %w", err)
	}

	return nil
}
