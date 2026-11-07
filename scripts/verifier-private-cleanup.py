#!/usr/bin/python3
"""Remove only a completed invocation's scratch, using inherited directory FDs.

No chmod through paths, no symlink following, no mount crossing, no retries.
The caller bounds wall time; entry/depth limits also fail closed.
"""
import os
import stat
import sys


def mount_id(fd):
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("mnt_id:"):
                return int(line.split()[1])
    raise RuntimeError("missing mount identity")


def cleanup(parent, root, name):
    if not name.startswith("verifier-private.") or "/" in name or name in (".", ".."):
        raise RuntimeError("invalid invocation name")
    identity = os.fstat(root)
    device, mount = identity.st_dev, mount_id(root)
    budget = 100000

    def checked(fd):
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise RuntimeError("not an invocation-owned directory")
        if info.st_dev != device or mount_id(fd) != mount:
            raise RuntimeError("refusing mount boundary")
        return info

    def same_entry(directory, entry, info):
        current = os.stat(entry, dir_fd=directory, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise RuntimeError("directory entry changed")

    def empty(fd, depth):
        nonlocal budget
        if depth > 128:
            raise RuntimeError("cleanup depth limit")
        info = checked(fd)
        # Go's normal 0555 module directories become writable only after the
        # sandbox exits. Files (including hard links) are never chmodded.
        os.fchmod(fd, stat.S_IMODE(info.st_mode) | 0o700)
        with os.scandir(fd) as entries:
            for entry in entries:
                budget -= 1
                if budget < 0:
                    raise RuntimeError("cleanup entry limit")
                item = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                if item.st_dev != device or item.st_uid != os.getuid():
                    raise RuntimeError("refusing foreign entry")
                if stat.S_ISDIR(item.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=fd)
                    try:
                        opened = checked(child)
                        same_entry(fd, entry.name, opened)
                        empty(child, depth + 1)
                        same_entry(fd, entry.name, opened)
                        os.rmdir(entry.name, dir_fd=fd)
                    finally:
                        os.close(child)
                else:
                    # unlink removes the owned entry itself, never its target.
                    os.unlink(entry.name, dir_fd=fd)

    checked(root)
    same_entry(parent, name, identity)
    empty(root, 0)
    same_entry(parent, name, identity)
    os.rmdir(name, dir_fd=parent)


if __name__ == "__main__":
    try:
        cleanup(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
    except (OSError, RuntimeError, ValueError, IndexError) as error:
        print(f"verifier cleanup: {error}", file=sys.stderr)
        sys.exit(1)
