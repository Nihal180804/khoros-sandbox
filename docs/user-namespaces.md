# Design: user namespace for the jail

**Status:** implemented (approach #2, defence-in-depth) in `src/main.cpp`,
exercised as root with the full escape suite (`make test && python3
scripts/escape_tests.py` — 14 smoke + 25 adversarial cases green, including a new
`runs inside a user namespace` assertion and the still-must-pass
mknod/mount/module/unshare cases).

The final shape differs from the sketch below in one important way, discovered
during implementation on a root-capable box (see "What actually works").

### What actually works

The sketch below (and a first implementation of it) unshared `CLONE_NEWUSER`
together with the other namespaces, up front, so that the leaf built the jail
*inside* the new user namespace. That fails: **a non-initial user namespace
cannot bind-mount a subdirectory out of the host's root mount when that mount has
locked submounts** — the rootfs bind returns `EPERM`. An unprivileged userns
(bubblewrap) escapes this because its mount tree is simpler; a root-created one
copies the whole locked tree and is refused.

So the order is inverted: the middle child unshares every namespace **except**
the user namespace, the leaf builds the entire filesystem jail (rootfs bind,
read-only remount, workspace, `/dev` via `mknod`, `pivot_root`) **as real host
root in the initial user namespace** — exactly as before this change — and only
*then* does the leaf `unshare(CLONE_NEWUSER)`, purely for the runtime
defence-in-depth property. Because the user namespace now comes after the
mounts, `/dev` keeps using `mknod` (no bind-mount workaround needed) and host
uid 0 never needs to be mapped.

### Realized mapping

The parent writes the leaf's maps (it alone holds `CAP_SETUID`/`CAP_SETGID` in
the initial userns; it learns the leaf's pid from the middle child and waits for
the leaf to signal that it has created the namespace). Two lines:

```
0   65534   1     inside-uid 0 -> host 65534 (nobody); a regained in-jail uid 0
                  is an unprivileged host uid
S   S       1     the per-run pool id, identity-mapped; the leaf drops to it and
                  the host sees workspace writes as that id, exactly as before
```

Host uid 0 is **not** mapped: the mounts already ran as real root before the
namespace existed, so the leaf never needs its host-0 fsuid mapped, and leaving
it out means real root is entirely unreachable from inside. The inside-0 line is
omitted when `S == 65534` (the CLI default), since two lines sharing a host id is
an invalid overlapping map; inside-0 is then simply unmapped and uid 0 is
unreachable. Pool ids (>= 100000) always get the full two-line map. See
`write_userns_maps` / `build_id_map` in `src/main.cpp`.

### One subtlety: the capability drop

The kernel's setuid fixup, which normally clears the effective and permitted
capability sets when a root process drops to a non-root uid, keys on the process
being uid 0 in the *initial* user namespace. The leaf is the owner of its *own*
user namespace (full capability set) with host uid 0 left unmapped, so the fixup
does not fire and the capabilities survive the `setresuid`. `drop_privileges`
therefore clears them explicitly with a `capset` to the empty set after the uid
drop; with the bounding set already empty and `NO_NEW_PRIVS` set, they cannot
return. The `no effective capabilities` and `cannot regain uid 0` escape cases
guard this.

## The gap

Today the leaf runs as an unprivileged uid (65534, or a per-run pool id) with an
empty capability bounding set, `NO_NEW_PRIVS`, and `SECBIT_NOROOT` locked. That
is strong. But the uid it drops to is a uid **in the initial user namespace**. If
some future bug let the process regain uid 0 — a kernel capability-handling flaw,
a mistake in the drop sequence — that uid 0 would be real host root.

The fix is to run the jail inside its own user namespace whose root maps to an
unprivileged host uid. Then "uid 0 inside the jail" is, by construction, an
unprivileged uid on the host. Regaining it buys nothing. This is exactly the
property rootless containers rely on.

## Approach: nested userns, keep the root-owned runner

Two end states are possible:

1. **Rootless** — drop the `sudo`/root requirement entirely; the runner is
   launched by an unprivileged user and `unshare(CLONE_NEWUSER)` grants the caps
   needed to build the rest of the jail *within the new userns*.
2. **Defence-in-depth (recommended first step)** — keep the existing root-owned,
   `sudo`-invoked runner and its validation, but add a user namespace for the
   leaf so a regained in-jail uid 0 is unprivileged on the host.

Start with (2): it is a smaller, verifiable delta over the current model and does
not give up any existing guarantee. (1) can follow once (2) is proven.

### Where it slots into the current flow

The middle child currently does:

```
unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC |
        CLONE_NEWUTS | CLONE_NEWCGROUP);
fork();  // leaf becomes PID 1
```

Add `CLONE_NEWUSER` to that `unshare`. The new userns must have its `uid_map` and
`gid_map` written **before** the process tries to act privileged inside it:

- `setgroups` must be set to `deny` (write `"deny"` to `/proc/<pid>/setgroups`)
  before `gid_map`, or the `gid_map` write is refused.
- Map a single id: inside-root → the unprivileged host id. Writing a map that
  covers host root requires `CAP_SETUID`/`CAP_SETGID` in the parent userns, which
  the root runner has. Example map `0 <host_uid> 1` makes in-jail uid 0 equal to
  host `<host_uid>`.
- The maps are written by a process that is **outside** the new userns but is the
  parent/owner of it — i.e. the middle child writes them for the leaf via
  `/proc/<leaf>/uid_map`, or the leaf blocks on a pipe until the middle child has
  written them. A sync pipe already exists for the cgroup handshake; mirror it.

Inside the new userns the leaf holds a full capability set **scoped to that
userns**, which is enough to `pivot_root`, `mount` `/proc` and the tmpfses, etc.
The existing privilege-drop sequence (securebits, bounding-set drop, `setresuid`
to an unprivileged id, the `setuid(0)`-must-fail assertion) still runs last and
still applies — it now drops caps that were only ever userns-scoped.

### The mknod problem (the one real complication)

`setup_filesystem_jail` currently builds `/dev` by `mknod`-ing `null`, `zero`,
`full`, `random`, `urandom`. **`mknod` of a device node is not permitted in a
non-initial user namespace**, even with `CAP_MKNOD` there — the kernel blocks
device-node creation outside the initial userns. So the `mknod` loop will fail
the moment the leaf is in a userns.

Replace it with bind mounts of the host device nodes, which is what rootless
containers do:

```
mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "size=1m,mode=755");
for each of null,zero,full,random,urandom:
    create an empty file /dev/<name>
    mount(host "/dev/<name>", "/dev/<name>", NULL, MS_BIND, NULL);
    remount that bind MS_RDONLY|MS_NOSUID|MS_NODEV ... (NODEV is fine for a bind
        of an existing node — the device identity is carried by the source)
```

The host `/dev/<name>` paths must be captured **before** `pivot_root` detaches
the old root, or bind-mounted from a pre-opened fd. Simplest: do the `/dev` bind
mounts from the host device nodes right after the rootfs bind and before
`pivot_root`, targeting `<new_root>/dev/...`.

### Order of operations (leaf)

1. Block until the middle child has written `uid_map`/`gid_map` (sync pipe).
2. `setup_filesystem_jail` — rootfs ro bind, workspace rw (and overlay if set),
   **bind host `/dev` nodes instead of mknod**, `pivot_root`, mount `/proc`,
   `/tmp`.
3. `drop_privileges` — unchanged; now dropping userns-scoped caps.
4. `apply_rlimits`, `install_seccomp_filter`, `execve`.

## Interactions to get right

- **`clone` seccomp filter.** The allowlist already refuses `clone` with any
  namespace flag, including `CLONE_NEWUSER`, so sandboxed code cannot nest a
  further userns to re-acquire caps. Keep that. (`unshare` is absent from the
  allowlist entirely.) No change needed, but the escape test for `unshare`/nested
  userns must stay green.
- **cgroup attachment** still happens from the root parent before the userns
  exists, so controller delegation and limits are unaffected.
- **Per-run uid pool** composes cleanly: the host id the userns maps to can be the
  pool id for that run.
- **`/proc/sys/user/max_user_namespaces`** must be non-zero on the host (it is:
  61163 on the dev box). Document it as a requirement.

## Tests this must add to `scripts/escape_tests.py`

- `/proc/self/uid_map` shows the single expected mapping, not an identity map.
- In-jail `os.getuid()` of 0 (if the program `setuid(0)`s within the userns) still
  maps to an unprivileged host id — assert via a host-side check that no file
  owned by real root was created.
- The existing `mknod refused`, `mount refused`, `core_pattern not writable` and
  `finit_module` cases must **still pass** — the userns must not hand back any
  host-affecting capability.
- `/dev/null` and `/dev/urandom` still readable/writable (regression guard for the
  mknod→bind switch).

## Note on the sketch below

The sections that follow are the original design sketch. They are kept for
context, but two of their conclusions were overtaken by "What actually works"
above:

- **The mknod problem** does not arise. Because the user namespace is created
  *after* the mounts (as real root), `/dev` still uses `mknod`; no host device
  bind mounts are needed.
- **The `unshare(CLONE_NEWUSER)` placement** moved from the middle child's
  combined unshare to a dedicated `unshare` in the leaf after `pivot_root`.

Everything else — the `setgroups`/map ordering, the `clone` seccomp interaction,
cgroup attachment, the per-run uid composition, and the test list — carried over
as written.
