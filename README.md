# runjail

runjail is a tool to create ad-hoc sandboxes on Linux.

It is intended to restrict access of the applications inside the sandbox
to your system but not to provide a completely different runtime environment
like Docker or Flatpak does.

A common use case might be quickly testing a new tool you just discovered
without allowing it access to all your data.

`runjail --rw . --net yes -- bash` opens a shell with access to just the
current directory.


# Features

* Mount paths read-write or read-only from the host inside the sandbox
* Disable network access
* Isolate from the host processes (separate PID and IPC namespace)
* Reduce the kernel attack surface using seccomp filters


# Security considerations

Without any parameters runjail mounts /etc, /sys and /usr read-only
in the sandbox. Additionally /proc is mounted.
Make sure these directiories don't contain any secret user-readable data
or disable access to them by passing `--hide PATH`.

In the default configuration X11 opens an anonymous socket which makes it
a bit more difficult to prevent sandboxed applications to connect to it.

You can either disable network access from the sandbox or start X11 with
the parameter `-nolisten local`.


# Usage

```
usage: runjail [--flag [--flag ...]] -- [command [command ...]]:
--bind-ro strings       Bind mount source file/directory from parent namespace to target read-only (format: "source:target").
--bind-ro-try strings   Bind mount source file/directory from parent namespace to target read-only (format: "source:target"). Ignores non-existent source.
--bind-rw strings       Bind mount source file/directory from parent namespace to target read-write (format: "source:target").
--bind-rw-try strings   Bind mount source file/directory from parent namespace to target read-write (format: "source:target"). Ignores non-existent source.
--config string         Fetch options from config file.
--cwd string            Set the current working directory. (default ".")
--debug                 Enable debug mode.
--empty strings         Mount empty tmpfs on the specified directory.
--env strings           Set the environment variable (format: "name=value").
--hide strings          Make file/directory inaccessible.
--hide-try strings      Make file/directory inaccessible. Ignore non-existent path.
--ipc                   Allow IPC (don't start an own IPC namespace).
--net string            Enable/disable network access <yes|no>. (default "no")
--profile strings       Enable predefined profile: <x11|wayland|flatpak>.
--ro strings            Mount file/directory from parent namespace read-only.
--ro-try strings        Mount file/directory from parent namespace read-only. Ignores non-existent source.
--rw strings            Mount file/directory from parent namespace read-write.
--rw-try strings        Mount file/directory from parent namespace read-write. Ignores non-existent source.
--seccomp string        Enable seccomp syscall filtering: <yes|devel|minimal|no>. (default "yes")
```


# Examples

* Open a shell with network access that can access the current directory

  `runjail --rw . --net yes -- bash`

* Run firefox in a completely separate home directory and only access to the Downloads folder

  `runjail --cwd ~ --bind-rw ~/firefox-test:~ --rw ~/Downloads --profile x11 --net=yes -- firefox -no-remote`


# Config

Instead of passing all settings on the command line you can use --config to read a config file.

A commented example is provided in [config-sample.yml](config-sample.yml)

Wherever paths are accepted `$UID`, `$USER`, `$HOME` and `$XDG_RUNTIME_DIR` with their respective values.


# Requirements

runjail is tested on Linux >= 5.9

It uses unprvileged user namespaces which is disabled by default on some
distributions.

To enable it on Debian (<= 10) the sysctl `kernel.unprivileged_userns_clone` needs
to be set to `1`.


# Building

Golang >= 1.18 and the development files for libseccomp are required.

runjail can be built by running `go build` inside a Git checkout or with
`go get -u github.com/debfx/runjail`


# License

Unless otherwise noted all code of runjail is licensed under the GNU General
Public License version 3 or (at your option) version 2.
The full text of the GPLv3 can be found in the LICENSE file.
