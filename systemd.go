package main

import (
	"context"
	"fmt"
	"os"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
)

func createSystemdScope(name string) error {
	ctx := context.TODO()
	dbusConn, err := systemdDbus.NewUserConnectionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to systemd user bus: %w", err)
	}
	defer dbusConn.Close()
	statusChan := make(chan string, 1)
	pid := os.Getpid()
	properties := []systemdDbus.Property{
		systemdDbus.PropPids(uint32(pid)),
	}
	var scopeName string
	if name == "" {
		scopeName = fmt.Sprintf("runjail-%d.scope", pid)
	} else {
		scopeName = fmt.Sprintf("runjail-%s-%d.scope", name, pid)
	}
	_, err = dbusConn.StartTransientUnitContext(ctx, scopeName, "fail", properties, statusChan)
	if err != nil {
		return fmt.Errorf("failed to start transient unit: %w", err)
	}

	return nil
}
