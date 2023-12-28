// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) Felix Geyer <debfx@fobos.de>

package main

import (
	"fmt"

	seccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

type seccompRule struct {
	Action   seccomp.ScmpAction
	Syscall  seccomp.ScmpSyscall
	Arg      uint
	Op       seccomp.ScmpCompareOp
	OpValue1 uint64
	OpValue2 uint64
}

func loadFilter(defaultAction seccomp.ScmpAction, debug bool, rules []seccompRule) (*seccomp.ScmpFilter, error) {
	filter, err := seccomp.NewFilter(defaultAction)
	if err != nil {
		return nil, fmt.Errorf("creating new filter failed: %w", err)
	}

	api_level, err := seccomp.GetAPI()
	if err != nil {
		return nil, fmt.Errorf("getting api version failed: %w", err)
	}

	if debug && api_level >= 3 {
		err = filter.SetLogBit(true)
		if err != nil {
			return nil, fmt.Errorf("enabling logging failed: %w", err)
		}
	}

	// enable binary tree optimization on larger filters
	if len(rules) > 32 && api_level >= 4 {
		err = filter.SetOptimize(2)
		// ignore error since it's not fatal
		if err != nil && debug {
			fmt.Printf("seccomp binary tree optimization not available: %v\n", err)
		}
	}

	for _, rule := range rules {
		if rule.Op != seccomp.CompareInvalid {
			condition, err := seccomp.MakeCondition(rule.Arg, rule.Op, rule.OpValue1, rule.OpValue2)
			if err != nil {
				return nil, fmt.Errorf("creating condition failed: %w", err)
			}
			err = filter.AddRuleConditional(rule.Syscall, rule.Action, []seccomp.ScmpCondition{condition})
			if err != nil {
				return nil, fmt.Errorf("adding conditional rule failed: %w", err)
			}
		} else {
			err := filter.AddRule(rule.Syscall, rule.Action)
			if err != nil {
				return nil, fmt.Errorf("adding rule failed: %w", err)
			}
		}
	}

	return filter, nil
}

func loadSeccomp(filterName string, debug bool) ([]*seccomp.ScmpFilter, error) {
	/*
		minimal:
			- allow by default
			- deny mount syscalls, chroot/pivot_root, new user namespace, ioctl(TIOCSTI)
		default:
			- ENOSYS by default
			- allow list of syscalls
			- EPERM on known syscalls
		devel:
			- like default, but addtionally allow ptrace

	*/

	filters := []*seccomp.ScmpFilter{}

	actionEperm := seccomp.ActErrno.SetReturnCode(int16(unix.EPERM))
	actionEnosys := seccomp.ActErrno.SetReturnCode(int16(unix.ENOSYS))
	actionEafnosupport := seccomp.ActErrno.SetReturnCode(int16(unix.EAFNOSUPPORT))

	var defaultActionMain seccomp.ScmpAction
	rulesMain := []seccompRule{}

	if filterName == "minimal" {
		defaultActionMain = seccomp.ActAllow

		for _, syscallName := range SeccompMinimalEperm {
			syscallNo, err := seccomp.GetSyscallFromName(syscallName)
			if err != nil {
				// skip syscalls that aren't available
				continue
			}
			rulesMain = append(rulesMain, seccompRule{
				Action:  actionEperm,
				Syscall: syscallNo,
			})
		}

		for _, syscallName := range SeccompMinimalEnosys {
			syscallNo, err := seccomp.GetSyscallFromName(syscallName)
			if err != nil {
				// skip syscalls that aren't available
				continue
			}
			rulesMain = append(rulesMain, seccompRule{
				Action:  actionEnosys,
				Syscall: syscallNo,
			})
		}
	} else {
		defaultActionMain = actionEnosys

		for _, syscallName := range SeccompAllow {
			syscallNo, err := seccomp.GetSyscallFromName(syscallName)
			if err != nil {
				// skip syscalls that aren't available
				continue
			}
			rulesMain = append(rulesMain, seccompRule{
				Action:  seccomp.ActAllow,
				Syscall: syscallNo,
			})
		}

		for _, syscallName := range SeccompEperm {
			syscallNo, err := seccomp.GetSyscallFromName(syscallName)
			if err != nil {
				// skip syscalls that aren't available
				continue
			}
			rulesMain = append(rulesMain, seccompRule{
				Action:  actionEperm,
				Syscall: syscallNo,
			})
		}

		var develAction seccomp.ScmpAction
		if filterName == "devel" {
			develAction = seccomp.ActAllow
		} else {
			develAction = actionEperm
		}

		for _, syscallName := range SeccompAllowDevel {
			syscallNo, err := seccomp.GetSyscallFromName(syscallName)
			if err != nil {
				// skip syscalls that aren't available
				continue
			}
			rulesMain = append(rulesMain, seccompRule{
				Action:  develAction,
				Syscall: syscallNo,
			})
		}

		// allow only AF_UNIX (1), AF_INET (2), AF_INET6 (10) and AF_NETLINK (16)
		for _, i := range []int{1, 2, 10, 16} {
			rulesMain = append(rulesMain, seccompRule{
				Action:   seccomp.ActAllow,
				Syscall:  unix.SYS_SOCKET,
				Arg:      0,
				Op:       seccomp.CompareEqual,
				OpValue1: uint64(i),
			})
		}

		rulesMain = append(rulesMain, seccompRule{
			Action:   actionEafnosupport,
			Syscall:  unix.SYS_SOCKET,
			Arg:      0,
			Op:       seccomp.CompareLess,
			OpValue1: 1,
		})
		rulesMain = append(rulesMain, seccompRule{
			Action:   actionEafnosupport,
			Syscall:  unix.SYS_SOCKET,
			Arg:      0,
			Op:       seccomp.CompareGreater,
			OpValue1: 16,
		})

		for i := 3; i < 10; i++ {
			rulesMain = append(rulesMain, seccompRule{
				Action:   actionEafnosupport,
				Syscall:  unix.SYS_SOCKET,
				Arg:      0,
				Op:       seccomp.CompareEqual,
				OpValue1: uint64(i),
			})
		}
		for i := 11; i < 16; i++ {
			rulesMain = append(rulesMain, seccompRule{
				Action:   actionEafnosupport,
				Syscall:  unix.SYS_SOCKET,
				Arg:      0,
				Op:       seccomp.CompareEqual,
				OpValue1: uint64(i),
			})
		}

		// only allow personality(PER_LINUX)
		rulesMain = append(rulesMain, seccompRule{
			Action:   seccomp.ActAllow,
			Syscall:  unix.SYS_PERSONALITY,
			Arg:      0,
			Op:       seccomp.CompareEqual,
			OpValue1: 0,
		})
		rulesMain = append(rulesMain, seccompRule{
			Action:   actionEperm,
			Syscall:  unix.SYS_PERSONALITY,
			Arg:      0,
			Op:       seccomp.CompareNotEqual,
			OpValue1: 0,
		})
	}

	filterMain, err := loadFilter(defaultActionMain, debug, rulesMain)
	if err != nil {
		return nil, fmt.Errorf("loading main seccomp filter failed: %w", err)
	}
	filters = append(filters, filterMain)

	rulesMaskedEqual := []seccompRule{
		// don't allow faking input to the controlling tty (CVE-2017-5226)
		{
			Action:   actionEperm,
			Syscall:  unix.SYS_IOCTL,
			Arg:      1,
			Op:       seccomp.CompareMaskedEqual,
			OpValue1: 0xFFFFFFFF,
			OpValue2: unix.TIOCSTI,
		},
		// block copy/paste operations on virtual consoles (CVE-2023-28100)
		{
			Action:   actionEperm,
			Syscall:  unix.SYS_IOCTL,
			Arg:      1,
			Op:       seccomp.CompareMaskedEqual,
			OpValue1: 0xFFFFFFFF,
			OpValue2: unix.TIOCLINUX,
		},
		// block creating a new user namespace
		{
			Action:   actionEperm,
			Syscall:  unix.SYS_CLONE,
			Arg:      0,
			Op:       seccomp.CompareMaskedEqual,
			OpValue1: unix.CLONE_NEWUSER,
			OpValue2: unix.CLONE_NEWUSER,
		},
	}

	filterMaskedEqual, err := loadFilter(seccomp.ActAllow, debug, rulesMaskedEqual)
	if err != nil {
		return nil, fmt.Errorf("loading masked-equal seccomp filter failed: %w", err)
	}
	// add after filterMain so it is evaluated first by the kernel
	filters = append(filters, filterMaskedEqual)

	return filters, nil
}
