// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) 2020-2022 Felix Geyer <debfx@fobos.de>

package main

import (
	"net"

	"github.com/vishvananda/netlink"
)

func setupLoopbackInterface() error {
	// the loopback interface is not up by default but automatically has 127.0.0.1/::1 IPs
	ifaceLo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	if err = netlink.LinkSetUp(ifaceLo); err != nil {
		return err
	}

	return nil
}

func addDummyInterface() error {
	const DummyInterfaceName = "dummy"
	err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: DummyInterfaceName}})
	if err != nil {
		return err
	}
	link, err := netlink.LinkByName(DummyInterfaceName)
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		return err
	}

	ipnet := &net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(24, 32)}
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.AddrAdd(link, addr)
	if err != nil {
		return err
	}

	return nil
}
