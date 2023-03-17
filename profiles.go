// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) 2020-2022 Felix Geyer <debfx@fobos.de>

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

type jailProfile struct {
	EnvVars  map[string]string
	Mounts   []mount
	Settings settingsStruct
}

func getX11Socket() (string, error) {
	display := os.Getenv("DISPLAY")

	if len(display) == 0 {
		return "", fmt.Errorf("DISPLAY environment variable is not set")
	}

	if len(display) < 2 || display[0] != ':' {
		return "", fmt.Errorf("DISPLAY environment variable is invalid (\"%s\")", display)
	}

	if _, err := strconv.Atoi(display[1:]); err != nil {
		return "", fmt.Errorf("DISPLAY environment variable is invalid (\"%s\")", display)
	}

	socketPath := fmt.Sprintf("/tmp/.X11-unix/X%s", display[1:])

	if _, err := os.Stat(socketPath); err != nil {
		return "", err
	}

	return socketPath, nil
}

func getWaylandSocket() (string, error) {
	socketPath := os.Getenv("WAYLAND_DISPLAY")
	if len(socketPath) == 0 {
		socketPath = "wayland-0"
	}

	if !strings.HasPrefix(socketPath, "/") {
		runtimeDir, err := getUserRuntimeDir()
		if err != nil {
			return "", err
		}

		socketPath = fmt.Sprintf("%s/%s", runtimeDir, socketPath)
	}

	if _, err := os.Stat(socketPath); err != nil {
		return "", err
	}

	return socketPath, nil
}

func getPortalDocDir() (string, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return "", fmt.Errorf("Failed to connect to session bus: %w", err)
	}
	defer conn.Close()

	portalDocuments := conn.Object("org.freedesktop.portal.Documents", "/org/freedesktop/portal/documents")

	var portalDirBytes []byte
	err = portalDocuments.Call("org.freedesktop.portal.Documents.GetMountPoint", 0).Store(&portalDirBytes)
	if err != nil {
		return "", fmt.Errorf("Failed to get portal documents dir: %w", err)
	}
	// result is a byte-encoded zero-terminated string
	portalDirBytesParts := bytes.Split(portalDirBytes, []byte("\x00"))
	return string(portalDirBytesParts[0]), nil
}

func getProfile(name string, settings settingsStruct) (jailProfile, error) {
	profile := jailProfile{
		EnvVars: map[string]string{},
		Mounts:  []mount{},
	}

	switch name {
	case "x11":
		x11Socket, err := getX11Socket()
		if err != nil {
			return profile, err
		}

		profile.Mounts = append(profile.Mounts, mount{Path: "/tmp/.X11-unix/X0", Other: x11Socket, Type: mountTypeBindRw})
		profile.EnvVars["DISPLAY"] = ":0"
	case "wayland":
		waylandSocket, err := getWaylandSocket()
		if err != nil {
			return profile, err
		}

		runtimeDir, err := getUserRuntimeDir()
		if err != nil {
			return profile, err
		}

		profile.Mounts = append(profile.Mounts, mount{Path: fmt.Sprintf("%s/wayland-0", runtimeDir), Other: waylandSocket, Type: mountTypeBindRw})
		profile.EnvVars["WAYLAND_DISPLAY"] = "wayland-0"
	case "flatpak":
		if settings.Name == "" {
			return profile, fmt.Errorf("flatpak profile requires a name config")
		}

		runtimeDir, err := getUserRuntimeDir()
		if err != nil {
			return profile, err
		}

		portalDir, err := getPortalDocDir()
		if err != nil {
			return profile, err
		}

		desktopFileContent := fmt.Sprintf("[Application]\nname=%s\n", settings.Name)
		flatpakInfo := base64.StdEncoding.EncodeToString([]byte(desktopFileContent))

		profile.Mounts = append(profile.Mounts, mount{Path: "/.flatpak-info", Other: flatpakInfo, Type: mountTypeFileData})
		// compatbility with older flatpak
		profile.Mounts = append(profile.Mounts, mount{Path: path.Join(runtimeDir, "flatpak-info"), Other: "/.flatpak-info", Type: mountTypeSymlink})

		profile.Mounts = append(profile.Mounts, mount{Path: path.Join(runtimeDir, "doc"), Other: path.Join(portalDir, "by-app", settings.Name), Type: mountTypeBindRw})
		profile.Mounts = append(profile.Mounts, mount{Path: "/usr/bin/xdg-email", Other: "/usr/libexec/flatpak-xdg-utils/xdg-email", Type: mountTypeBindRo})
		profile.Mounts = append(profile.Mounts, mount{Path: "/usr/bin/xdg-open", Other: "/usr/libexec/flatpak-xdg-utils/xdg-open", Type: mountTypeBindRo})

		profile.Settings.DbusCall = append(profile.Settings.DbusCall, "org.freedesktop.portal.*=*")
		profile.Settings.DbusBroadcast = append(profile.Settings.DbusBroadcast, "org.freedesktop.portal.*=@/org/freedesktop/portal/*")
	default:
		return profile, fmt.Errorf("profile \"%s\" doesn't exist", name)
	}

	return profile, nil
}
