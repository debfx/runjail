package main

import (
	"context"
	"fmt"
	"os"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
)

func createSystemdScope() error {
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
	_, err = dbusConn.StartTransientUnitContext(ctx, fmt.Sprintf("runjail-%d.scope", pid), "fail", properties, statusChan)
	if err != nil {
		return fmt.Errorf("failed to start transient unit: %w", err)
	}

	return nil
}
