// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) 2020-2022 Felix Geyer <debfx@fobos.de>

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

type StringArray []string

type configStruct struct {
	Ro            StringArray       `yaml:"ro"`
	RoTry         StringArray       `yaml:"ro_try"`
	Rw            StringArray       `yaml:"rw"`
	RwTry         StringArray       `yaml:"rw_try"`
	Hide          StringArray       `yaml:"hide"`
	HideTry       StringArray       `yaml:"hide_try"`
	Empty         StringArray       `yaml:"empty"`
	BindRo        map[string]string `yaml:"bind_ro"`
	BindRoTry     map[string]string `yaml:"bind_ro_try"`
	BindRw        map[string]string `yaml:"bind_rw"`
	BindRwTry     map[string]string `yaml:"bind_rw_try"`
	Network       string            `yaml:"network"`
	AllowedHosts  []string          `yaml:"allowed_hosts"`
	Ipc           *bool             `yaml:"ipc"`
	DbusOwn       []string          `yaml:"dbus_own"`
	DbusTalk      []string          `yaml:"dbus_talk"`
	DbusCall      []string          `yaml:"dbus_call"`
	DbusBroadcast []string          `yaml:"dbus_broadcast"`
	Cwd           string            `yaml:"cwd"`
	Environment   map[string]string `yaml:"environment"`
	Seccomp       string            `yaml:"seccomp"`
	Profiles      StringArray       `yaml:"profiles"`
	Name          string            `yaml:"name"`
	SystemdUnit   *bool             `yaml:"systemd_unit"`
	Command       StringArray       `yaml:"command"`
}

// parse yaml array as slice
// parse yaml string as slice with one entry
func (a *StringArray) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var multi []string
	err := unmarshal(&multi)
	if err != nil {
		var single string
		err := unmarshal(&single)
		if err != nil {
			return err
		}
		*a = []string{single}
	} else {
		*a = multi
	}
	return nil
}

func replaceAllSlice(list []string, replacer *strings.Replacer) {
	for i, value := range list {
		list[i] = replacer.Replace(value)
	}
}

func replaceAllMap(stringMap map[string]string, replacer *strings.Replacer) {
	for key, value := range stringMap {
		stringMap[key] = replacer.Replace(value)
	}
}

func parseConfig(path string) (configStruct, error) {
	configContent, err := os.ReadFile(path)
	if err != nil {
		return configStruct{}, fmt.Errorf("failed to read config file: %w", err)
	}

	var config configStruct
	err = yaml.Unmarshal(configContent, &config)
	if err != nil {
		return configStruct{}, fmt.Errorf("failed to parse config file: %w", err)
	}

	username, err := getUsername()
	if err != nil {
		return configStruct{}, fmt.Errorf("failed to get username: %w", err)
	}

	homeDir, err := getUserHomeDir()
	if err != nil {
		return configStruct{}, fmt.Errorf("failed to get user home dir: %w", err)
	}

	runtimeDir, err := getUserRuntimeDir()
	if err != nil {
		return configStruct{}, fmt.Errorf("failed to get user runtime dir: %w", err)
	}

	replacer := strings.NewReplacer(
		"$UID", strconv.Itoa(os.Getuid()),
		"$USER", username,
		"$HOME", homeDir,
		"$XDG_RUNTIME_DIR", runtimeDir,
	)

	replaceAllSlice(config.Ro, replacer)
	replaceAllSlice(config.RoTry, replacer)
	replaceAllSlice(config.Rw, replacer)
	replaceAllSlice(config.RwTry, replacer)
	replaceAllSlice(config.Hide, replacer)
	replaceAllSlice(config.HideTry, replacer)
	replaceAllSlice(config.Empty, replacer)
	replaceAllSlice(config.Command, replacer)

	replaceAllMap(config.BindRo, replacer)
	replaceAllMap(config.BindRoTry, replacer)
	replaceAllMap(config.BindRw, replacer)
	replaceAllMap(config.BindRwTry, replacer)

	return config, nil
}
