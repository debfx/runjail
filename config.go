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
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type StringArray []string

type configStruct struct {
	Ro            StringArray       `yaml:"ro"`
	Rw            StringArray       `yaml:"rw"`
	Hide          StringArray       `yaml:"hide"`
	Empty         StringArray       `yaml:"empty"`
	BindRo        map[string]string `yaml:"bind_ro"`
	BindRw        map[string]string `yaml:"bind_rw"`
	Network       string            `yaml:"network"`
	Ipc           *bool             `yaml:"ipc"`
	DbusOwn       []string          `yaml:"dbus_own"`
	DbusTalk      []string          `yaml:"dbus_talk"`
	DbusCall      []string          `yaml:"dbus_call"`
	DbusBroadcast []string          `yaml:"dbus_broadcast"`
	Cwd           string            `yaml:"cwd"`
	Seccomp       string            `yaml:"seccomp"`
	Profiles      StringArray       `yaml:"profiles"`
	FlatpakName   string            `yaml:"flatpak_name"`
	Command       StringArray       `yaml:"command"`
	Backend       string            `yaml:"backend"`
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

func parseConfig(path string) (config configStruct, err error) {
	configContent, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}
	err = yaml.Unmarshal(configContent, &config)
	return
}
