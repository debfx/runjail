// SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
// Copyright (C) Felix Geyer <debfx@fobos.de>

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var regexpOctalEscape = regexp.MustCompile(`\\(\d{1,3})`)

var optionFlagMap = map[string]int{
	"ro":          unix.MS_RDONLY,
	"noexec":      unix.MS_NOEXEC,
	"nosuid":      unix.MS_NOSUID,
	"nodev":       unix.MS_NODEV,
	"sync":        unix.MS_SYNCHRONOUS,
	"dirsync":     unix.MS_DIRSYNC,
	"silent":      unix.MS_SILENT,
	"mand":        unix.MS_MANDLOCK,
	"noatime":     unix.MS_NOATIME,
	"iversion":    unix.MS_I_VERSION,
	"nodiratime":  unix.MS_NODIRATIME,
	"relatime":    unix.MS_RELATIME,
	"strictatime": unix.MS_STRICTATIME,
}

type mountInfoEntry struct {
	mountId        string
	parentId       string
	major          uint32
	minor          uint32
	root           string
	mountPoint     string
	mountOptions   string
	optionalFields []string
	fsType         string
	mountSource    string
	superOptions   string
}

func (mie *mountInfoEntry) mountFlags() int {
	flags := 0

	for _, option := range strings.Split(mie.mountOptions, ",") {
		flag, ok := optionFlagMap[option]
		if ok {
			flags = flags | flag
		}
	}

	return flags
}

func octalToChar(match string) string {
	codepoint, _ := strconv.ParseInt(match, 8, 8)
	return string(rune(codepoint))
}

func unescapeField(field string) string {
	return regexpOctalEscape.ReplaceAllStringFunc(field, octalToChar)
}

func parseMountInfo(pathPrefix string, mountInfoPath string) ([]mountInfoEntry, error) {
	f, err := os.OpenFile(mountInfoPath, os.O_RDONLY, 0)
	if err != nil {
		return []mountInfoEntry{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	result := []mountInfoEntry{}
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Split(line, " ")

		for i := range fields {
			fields[i] = unescapeField(fields[i])
		}

		indexDash := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				indexDash = i
			}
		}
		if indexDash == -1 {
			return []mountInfoEntry{}, fmt.Errorf("missing optional fields separator")
		}
		if len(fields)-indexDash-1 < 3 {
			return []mountInfoEntry{}, fmt.Errorf("not enough fields after optional")
		}

		deviceParts := strings.Split(fields[2], ":")
		if len(deviceParts) != 2 {
			return []mountInfoEntry{}, fmt.Errorf("invalid major:minor field")
		}
		major, err := strconv.ParseUint(deviceParts[0], 10, 32)
		if err != nil {
			return []mountInfoEntry{}, fmt.Errorf("invalid major value")
		}
		minor, err := strconv.ParseUint(deviceParts[1], 10, 32)
		if err != nil {
			return []mountInfoEntry{}, fmt.Errorf("invalid minor value")
		}

		entry := mountInfoEntry{
			mountId:        fields[0],
			parentId:       fields[1],
			major:          uint32(major),
			minor:          uint32(minor),
			root:           fields[3],
			mountPoint:     fields[4],
			mountOptions:   fields[5],
			optionalFields: fields[6:indexDash],
			fsType:         fields[indexDash+1],
			mountSource:    fields[indexDash+2],
			superOptions:   fields[indexDash+3],
		}

		if entry.mountPoint == pathPrefix || strings.HasPrefix(entry.mountPoint, pathPrefix+"/") {
			result = append(result, entry)
		}

	}
	if err := sc.Err(); err != nil {
		return []mountInfoEntry{}, err
	}

	return result, nil
}
