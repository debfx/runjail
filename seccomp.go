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
	"syscall"

	seccomp "github.com/seccomp/libseccomp-golang"
)

type seccompRule struct {
	Action   seccomp.ScmpAction
	Syscall  seccomp.ScmpSyscall
	Arg      uint
	Op       seccomp.ScmpCompareOp
	OpValue1 uint64
	OpValue2 uint64
}

func loadSeccomp(filterName string, logDenials bool) (*seccomp.ScmpFilter, error) {

	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return nil, err
	}

	api_level, err := seccomp.GetApi()
	if err != nil {
		return nil, err
	}

	if logDenials && api_level >= 3 {
		err = filter.SetLogBit(true)
		if err != nil {
			return nil, err
		}
	}

	rules := []seccompRule{}
	actionEperm := seccomp.ActErrno.SetReturnCode(int16(syscall.EPERM))
	actionEafnosupport := seccomp.ActErrno.SetReturnCode(int16(syscall.EAFNOSUPPORT))

	// don't allow faking input to the controlling tty (CVE-2017-5226) / block TIOCSTI
	rules = append(rules, seccompRule{
		Action:   actionEperm,
		Syscall:  syscall.SYS_IOCTL,
		Arg:      1,
		Op:       seccomp.CompareMaskedEqual,
		OpValue1: 0xFFFFFFFF,
		OpValue2: syscall.TIOCSTI})

	if filterName != "minimal" {
		// allow only AF_UNIX (1), AF_INET (2), AF_INET6 (10) and AF_NETLINK (16)
		rules = append(rules, seccompRule{
			Action:   actionEafnosupport,
			Syscall:  syscall.SYS_SOCKET,
			Arg:      0,
			Op:       seccomp.CompareLess,
			OpValue1: 1})
		rules = append(rules, seccompRule{
			Action:   actionEafnosupport,
			Syscall:  syscall.SYS_SOCKET,
			Arg:      0,
			Op:       seccomp.CompareGreater,
			OpValue1: 16})

		for i := 3; i < 10; i++ {
			rules = append(rules, seccompRule{
				Action:   actionEafnosupport,
				Syscall:  syscall.SYS_SOCKET,
				Arg:      0,
				Op:       seccomp.CompareEqual,
				OpValue1: uint64(i)})
		}
		for i := 11; i < 16; i++ {
			rules = append(rules, seccompRule{
				Action:   actionEafnosupport,
				Syscall:  syscall.SYS_SOCKET,
				Arg:      0,
				Op:       seccomp.CompareEqual,
				OpValue1: uint64(i)})
		}

		blockedSyscalls := []string{
			// copied from systemd

			// @chown
			// Change ownership of files and directories
			"chown",
			"chown32",
			"fchown",
			"fchown32",
			"fchownat",
			"lchown",
			"lchown32",

			// @clock
			// Change the system time
			"adjtimex",
			"clock_adjtime",
			"clock_adjtime64",
			"clock_settime",
			"clock_settime64",
			"settimeofday",

			// @cpu-emulation
			// System calls for CPU emulation functionality
			"modify_ldt",
			"subpage_prot",
			"switch_endian",
			"vm86",
			"vm86old",

			// @debug
			// Debugging, performance monitoring and tracing functionality
			"lookup_dcookie",
			"perf_event_open",
			"pidfd_getfd",
			"ptrace",
			"rtas",
			"s390_runtime_instr",
			"sys_debug_setcontext",

			// @keyring
			// Kernel keyring access",
			"add_key",
			"keyctl",
			"request_key",

			// @module
			// Loading and unloading of kernel modules
			"delete_module",
			"finit_module",
			"init_module",

			// @mount
			// Mounting and unmounting of file systems
			"chroot",
			"fsconfig",
			"fsmount",
			"fsopen",
			"fspick",
			"mount",
			"mount_setattr",
			"move_mount",
			"open_tree",
			"pivot_root",
			"umount",
			"umount2",

			// @obsolete
			// Unusual, obsolete or unimplemented system calls
			"_sysctl",
			"afs_syscall",
			"bdflush",
			"break",
			"create_module",
			"ftime",
			"get_kernel_syms",
			"getpmsg",
			"gtty",
			"idle",
			"lock",
			"mpx",
			"prof",
			"profil",
			"putpmsg",
			"query_module",
			"security",
			"sgetmask",
			"ssetmask",
			"stime",
			"stty",
			"sysfs",
			"tuxcall",
			"ulimit",
			"uselib",
			"ustat",
			"vserver",

			// @privileged
			// All system calls which need super-user capabilities
			"_sysctl",
			"acct",
			"bpf",
			//"capset",
			"chroot",
			"fanotify_init",
			"fanotify_mark",
			"nfsservctl",
			"open_by_handle_at",
			"pivot_root",
			"quotactl",
			"setdomainname",
			"setfsuid",
			"setfsuid32",
			"setgroups",
			"setgroups32",
			"sethostname",
			"setresuid",
			"setresuid32",
			"setreuid",
			"setreuid32",
			"setuid",
			"setuid32",
			"vhangup",

			// @raw-io
			// Raw I/O port access
			"ioperm",
			"iopl",
			"pciconfig_iobase",
			"pciconfig_read",
			"pciconfig_write",
			"s390_pci_mmio_read",
			"s390_pci_mmio_write",

			// @reboot
			// Reboot and reboot preparation/kexec
			"kexec_file_load",
			"kexec_load",
			"reboot",

			// @setuid
			// Operations for changing user/group credentials
			"setgid",
			"setgid32",
			"setgroups",
			"setgroups32",
			"setregid",
			"setregid32",
			"setresgid",
			"setresgid32",
			"setresuid",
			"setresuid32",
			"setreuid",
			"setreuid32",
			"setuid",
			"setuid32",

			// @swap
			// Enable/disable swap devices
			"swapoff",
			"swapon",

			// @resources
			// Alter resource settings
			"ioprio_set",
			"mbind",
			"migrate_pages",
			"move_pages",
			//"nice",
			"sched_setaffinity",
			"sched_setattr",
			"sched_setparam",
			"sched_setscheduler",
			"set_mempolicy",
			//"setpriority",
			//"setrlimit",

			// namespaces
			"unshare",
			"setns",
		}

		for _, syscallName := range blockedSyscalls {
			syscallNo, err := seccomp.GetSyscallFromName(syscallName)
			if err != nil {
				// skip syscalls that aren't available
				continue
			}
			rules = append(rules, seccompRule{
				Action:  actionEperm,
				Syscall: syscallNo})
		}

		rules = append(rules, seccompRule{
			Action:   actionEperm,
			Syscall:  syscall.SYS_CLONE,
			Arg:      0,
			Op:       seccomp.CompareMaskedEqual,
			OpValue1: syscall.CLONE_NEWUSER,
			OpValue2: syscall.CLONE_NEWUSER})

		// only allow personality(PER_LINUX)
		rules = append(rules, seccompRule{
			Action:   actionEperm,
			Syscall:  syscall.SYS_PERSONALITY,
			Arg:      0,
			Op:       seccomp.CompareNotEqual,
			OpValue1: 0})
	}

	for _, rule := range rules {
		if rule.Op != seccomp.CompareInvalid {
			condition, err := seccomp.MakeCondition(rule.Arg, rule.Op, rule.OpValue1, rule.OpValue2)
			if err != nil {
				return nil, err
			}
			err = filter.AddRuleConditional(rule.Syscall, rule.Action, []seccomp.ScmpCondition{condition})
			if err != nil {
				return nil, err
			}
		} else {
			err := filter.AddRule(rule.Syscall, rule.Action)
			if err != nil {
				return nil, err
			}
		}
	}

	return filter, nil
}
