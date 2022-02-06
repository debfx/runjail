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

Without any parameters runjail mounts /etc, /sys, /usr and /var read-only
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
--bind-ro strings   Bind mount source file/directory from parent namespace to target read-only (Format: "source:target").
--bind-rw strings   Bind mount source file/directory from parent namespace to target read-write (Format: "source:target").
--config string     Fetch options from config file.
--cwd string        Set the current working directory. (default ".")
--debug             Enable debug mode.
--empty strings     Mount empty tmpfs on the specified path.
--hide strings      Make file/directory inaccessible.
--ipc               Allow IPC (don't start an own IPC namespace).
--net string        Enable/disable network access (yes/no). (default "no")
--profile strings   Enable predefined profiles (x11/wayland/flatpak).
--ro strings        Mount file/directory from parent namespace read-only.
--rw strings        Mount file/directory from parent namespace read-write.
--seccomp string    Enable seccomp syscall filtering (yes/minimal/no). (default "yes")
```


# Examples

* Open a shell with network access that can access the current directory

  `runjail --rw . --net yes -- bash`

* Run firefox in a completely separate home directory and only access to the Downloads folder

  `runjail --cwd ~ --bind-rw ~/firefox-test:~ --rw ~/Downloads --profile x11 --net=yes -- firefox -no-remote`


# Requirements

runjail is tested on Linux >= 4.19

It uses unprvileged user namespaces which is disabled by default on some
distributions.

To enable it on Debian the sysctl `kernel.unprivileged_userns_clone` needs
to be set to `1`.


# Building

Golang >= 1.13 and the development files for libseccomp are required.

runjail can be built by running `go build` inside a Git checkout or with
`go get -u github.com/debfx/runjail`
