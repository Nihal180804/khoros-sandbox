// Khoros Sandbox - hardened host runner
//
// Isolation model (in order of application):
//   parent (root) : validate args, resolve rootfs from /proc/self/exe, create cgroup,
//                   enable controllers, apply memory/pids/cpu limits, arm watchdog
//   middle child  : unshare(NET|PID|NS|IPC|UTS|CGROUP), fork leaf (leaf becomes PID 1)
//   leaf          : read-only rootfs bind, RW workspace bind, private /proc /dev /tmp,
//                   pivot_root, NO_NEW_PRIVS, securebits, capability bounding set drop,
//                   setgid/setuid to an unprivileged id, rlimits, seccomp allowlist, execve
//
// The leaf never executes untrusted code with uid 0 or any capability.

#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Fallback definitions (older headers)
// ---------------------------------------------------------------------------
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

// issecure_mask(SECURE_NOROOT) | issecure_mask(SECURE_NOROOT_LOCKED)
//   | issecure_mask(SECURE_KEEP_CAPS_LOCKED)
// SECURE_NO_SETUID_FIXUP is deliberately NOT set: we rely on the default
// setuid fixup to clear the effective and permitted capability sets.
static constexpr unsigned long KH_SECUREBITS =
    (1UL << 0) | (1UL << 1) | (1UL << 5);

// ---------------------------------------------------------------------------
// Configuration limits (hard ceilings; the API may request less, never more)
// ---------------------------------------------------------------------------
static constexpr int      MAX_TIMEOUT_SEC   = 60;
static constexpr int      MIN_TIMEOUT_SEC   = 1;
static constexpr int      MAX_MEM_MB        = 2048;
static constexpr int      MIN_MEM_MB        = 8;
static constexpr int      MAX_PIDS          = 256;
static constexpr size_t   MAX_STREAM_BYTES  = 1u << 20;   // 1 MiB per stream
static constexpr rlim_t   RLIMIT_FSIZE_BYTES = 64ull << 20;
static constexpr rlim_t   RLIMIT_NOFILE_MAX  = 256;
static constexpr uid_t    DEFAULT_SANDBOX_UID = 65534;    // nobody
static constexpr gid_t    DEFAULT_SANDBOX_GID = 65534;

static const char* CGROUP_PARENT = "/sys/fs/cgroup/sandbox_demo";

// ---------------------------------------------------------------------------
// Globals touched from the signal handler (async-signal-safe only)
// ---------------------------------------------------------------------------
static volatile sig_atomic_t g_timed_out = 0;
static int                   g_kill_fd   = -1;   // pre-opened cgroup.kill
static volatile pid_t        g_child_pid = -1;

// Set once the workspace has been handed to the sandbox uid. Any exit after
// that point must hand it back, or the API user is left with a directory it
// cannot remove.
static std::string           g_restore_ws;
static void restore_workdir_owner(const std::string& host_ws);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
static void die(const char* msg) {
    fprintf(stderr, "khoros: %s", msg);
    if (errno) fprintf(stderr, ": %s", strerror(errno));
    fprintf(stderr, "\n");
    if (!g_restore_ws.empty()) restore_workdir_owner(g_restore_ws);
    _exit(2);
}

// Used by the leaf after fork: never returns to the caller's control flow.
static void die_child(const char* msg) {
    fprintf(stderr, "khoros(jail): %s: %s\n", msg, strerror(errno));
    _exit(126);
}

// Returns the length of the valid UTF-8 sequence starting at s[i], or 0 if the
// bytes there are not valid UTF-8. Rejects overlong forms, surrogates and
// out-of-range code points so the emitted JSON is always decodable.
static size_t utf8_seq_len(const std::string& s, size_t i) {
    const size_t n = s.size();
    unsigned char c0 = static_cast<unsigned char>(s[i]);
    size_t len;
    unsigned int cp;

    if      (c0 < 0x80)                   return 1;
    else if ((c0 & 0xe0) == 0xc0) { len = 2; cp = c0 & 0x1f; }
    else if ((c0 & 0xf0) == 0xe0) { len = 3; cp = c0 & 0x0f; }
    else if ((c0 & 0xf8) == 0xf0) { len = 4; cp = c0 & 0x07; }
    else return 0;

    if (i + len > n) return 0;
    for (size_t k = 1; k < len; ++k) {
        unsigned char ck = static_cast<unsigned char>(s[i + k]);
        if ((ck & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (ck & 0x3f);
    }
    if (len == 2 && cp < 0x80)    return 0;   // overlong
    if (len == 3 && cp < 0x800)   return 0;
    if (len == 4 && cp < 0x10000) return 0;
    if (cp > 0x10ffff)            return 0;
    if (cp >= 0xd800 && cp <= 0xdfff) return 0;  // surrogate half
    return len;
}

// Produces valid JSON for arbitrary program output: control bytes are escaped,
// well-formed UTF-8 passes through untouched, and invalid bytes become U+FFFD
// one byte at a time. Binary stdout can no longer break the API's json.loads.
static std::string escape_json(const std::string& in) {
    std::ostringstream ss;
    for (size_t i = 0; i < in.size(); ) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        switch (c) {
            case '"':  ss << "\\\""; ++i; continue;
            case '\\': ss << "\\\\"; ++i; continue;
            case '\b': ss << "\\b";  ++i; continue;
            case '\f': ss << "\\f";  ++i; continue;
            case '\n': ss << "\\n";  ++i; continue;
            case '\r': ss << "\\r";  ++i; continue;
            case '\t': ss << "\\t";  ++i; continue;
            default: break;
        }
        if (c < 0x20 || c == 0x7f) {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04x", c);
            ss << buf;
            ++i;
        } else if (c < 0x80) {
            ss << static_cast<char>(c);
            ++i;
        } else {
            size_t len = utf8_seq_len(in, i);
            if (len == 0) {
                ss << "\\ufffd";
                ++i;
            } else {
                ss.write(in.data() + i, static_cast<std::streamsize>(len));
                i += len;
            }
        }
    }
    return ss.str();
}

static bool write_file(const std::string& path, const std::string& value) {
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t n = write(fd, value.c_str(), value.size());
    close(fd);
    return n == static_cast<ssize_t>(value.size());
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// run_id lands in a filesystem path, so it must not be able to escape it.
static bool valid_run_id(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

// workdir is a path relative to the rootfs, e.g. "workspace/task_ab12cd34".
static bool valid_rel_path(const std::string& s) {
    if (s.empty() || s.size() > 256) return false;
    if (s.front() == '/' ) return false;
    if (s.find("..") != std::string::npos) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '/' ||
                  c == '.';
        if (!ok) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Rootfs resolution
//
// The old code used realpath("./rootfs"), which is cwd-relative. Combined with
// a NOPASSWD sudoers entry that let any local user stage their own ./rootfs and
// pivot_root into it as root. The rootfs is now derived from the location of
// the runner binary and must be owned by root and not writable by anyone else.
// ---------------------------------------------------------------------------
static std::string resolve_rootfs() {
    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0) die("readlink /proc/self/exe");
    exe[n] = '\0';

    std::string dir(exe);
    size_t slash = dir.rfind('/');
    if (slash == std::string::npos) die("cannot determine runner directory");
    dir.resize(slash);

    std::string rootfs = dir + "/rootfs";
    char resolved[PATH_MAX];
    if (!realpath(rootfs.c_str(), resolved)) {
        fprintf(stderr, "khoros: rootfs not found at %s (run 'make bootstrap')\n",
                rootfs.c_str());
        _exit(2);
    }

    struct stat st;
    if (lstat(resolved, &st) < 0) die("stat rootfs");
    if (!S_ISDIR(st.st_mode)) die("rootfs is not a directory");
    if (st.st_uid != 0) {
        fprintf(stderr, "khoros: refusing to use rootfs %s: not owned by root\n",
                resolved);
        _exit(2);
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        fprintf(stderr,
                "khoros: refusing to use rootfs %s: group/world writable\n",
                resolved);
        _exit(2);
    }
    return std::string(resolved);
}

// ---------------------------------------------------------------------------
// cgroups v2
// ---------------------------------------------------------------------------

// In cgroup2 a child cgroup only gets memory.max / pids.max / cpu.max if the
// PARENT delegates those controllers via cgroup.subtree_control. The previous
// version never did this, so on a host where systemd had not already enabled
// them the limit files did not exist, every ofstream open failed, and the run
// proceeded with no memory limit and no pid limit at all.
static void ensure_parent_controllers() {
    struct stat st;
    if (stat(CGROUP_PARENT, &st) < 0) {
        fprintf(stderr,
                "khoros: %s missing. Create it with:\n"
                "  sudo mkdir -p %s\n",
                CGROUP_PARENT, CGROUP_PARENT);
        _exit(2);
    }

    const std::string ctl = std::string(CGROUP_PARENT) + "/cgroup.subtree_control";
    std::string current = read_file(ctl);

    // Enable one at a time so a host without the cpu controller still gets the
    // security-relevant memory and pids limits.
    struct { const char* name; bool required; } controllers[] = {
        {"memory", true}, {"pids", true}, {"cpu", false},
    };
    for (auto& c : controllers) {
        if (current.find(c.name) != std::string::npos) continue;
        if (write_file(ctl, std::string("+") + c.name + "\n")) continue;
        if (c.required) {
            fprintf(stderr,
                    "khoros: cannot delegate the '%s' controller to %s, so the "
                    "corresponding limit could not be enforced. Check that the "
                    "host mounts cgroup2 and enables %s at the root cgroup.\n",
                    c.name, CGROUP_PARENT, c.name);
            _exit(2);
        }
        fprintf(stderr, "khoros: warning: '%s' controller unavailable; "
                        "cpu.max will not be enforced\n", c.name);
    }
}

struct CgroupLimits {
    int    mem_mb;
    int    pids_max;
    double cpus;
};

// Fail-closed: any failure here aborts before untrusted code runs.
static std::string setup_cgroup(pid_t pid, const std::string& run_id,
                                const CgroupLimits& lim) {
    std::string path = std::string(CGROUP_PARENT) + "/" + run_id;

    if (mkdir(path.c_str(), 0700) < 0 && errno != EEXIST) die("mkdir cgroup");

    // memory.swap.max may be absent when swap accounting is compiled out. Treat
    // that as fatal rather than silently allowing swap-based limit evasion.
    if (!write_file(path + "/memory.swap.max", "0\n"))
        die("write memory.swap.max (swap accounting disabled?)");

    if (!write_file(path + "/memory.max",
                    std::to_string(static_cast<long long>(lim.mem_mb) * 1024 * 1024) + "\n"))
        die("write memory.max");

    if (!write_file(path + "/pids.max", std::to_string(lim.pids_max) + "\n"))
        die("write pids.max");

    // cpu.max bounds CPU time per period so one run cannot saturate every core
    // for the whole wall-clock budget.
    long long period = 100000;
    long long quota  = static_cast<long long>(lim.cpus * period);
    if (quota < 1000) quota = 1000;
    // Non-fatal: ensure_parent_controllers() has already warned if the cpu
    // controller is unavailable on this host.
    if (!write_file(path + "/cpu.max",
                    std::to_string(quota) + " " + std::to_string(period) + "\n"))
        fprintf(stderr, "khoros: warning: could not set cpu.max\n");

    if (!write_file(path + "/cgroup.procs", std::to_string(pid) + "\n"))
        die("attach pid to cgroup.procs");

    return path;
}

static unsigned long long read_peak_memory(const std::string& cgroup_path) {
    std::string s = read_file(cgroup_path + "/memory.peak");
    if (s.empty()) return 0;
    try { return std::stoull(s); } catch (...) { return 0; }
}

// memory.events tells us whether the kernel OOM-killed the task, which lets us
// report MEMORY_LIMIT_EXCEEDED separately from TIME_LIMIT_EXCEEDED instead of
// collapsing both into one ambiguous verdict.
static bool was_oom_killed(const std::string& cgroup_path) {
    std::string s = read_file(cgroup_path + "/memory.events");
    size_t pos = s.find("oom_kill ");
    if (pos == std::string::npos) return false;
    try { return std::stoull(s.substr(pos + 9)) > 0; } catch (...) { return false; }
}

// ---------------------------------------------------------------------------
// Workspace cleanup
//
// The workspace is chowned to the sandbox uid so the jailed process can write
// its compiler output, which means the unprivileged API user can no longer
// remove files the sandbox created. The runner, which already holds the
// privilege that created the situation, clears the directory itself.
//
// unlinkat never follows symlinks on the final component and directories are
// only descended into after an fstatat with AT_SYMLINK_NOFOLLOW, so a symlink
// planted in the workspace cannot redirect these deletions.
// ---------------------------------------------------------------------------
static constexpr int MAX_CLEANUP_DEPTH = 64;

static void rm_contents_at(int dirfd, int depth) {
    DIR* d = fdopendir(dirfd);          // takes ownership of dirfd
    if (!d) { close(dirfd); return; }

    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;

        struct stat st;
        if (fstatat(dirfd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (depth < MAX_CLEANUP_DEPTH) {
                int sub = openat(dirfd, e->d_name,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (sub >= 0) rm_contents_at(sub, depth + 1);
            }
            // The sandbox may have chmod'ed the directory unreadable.
            (void)!fchmodat(dirfd, e->d_name, 0700, 0);
            (void)!unlinkat(dirfd, e->d_name, AT_REMOVEDIR);
        } else {
            (void)!unlinkat(dirfd, e->d_name, 0);
        }
    }
    closedir(d);                        // closes dirfd
}

// Under sudo our real uid is also 0, so the owner to hand the directory back to
// comes from SUDO_UID/SUDO_GID when present.
static void caller_ids(uid_t& uid, gid_t& gid) {
    uid = getuid();
    gid = getgid();
    const char* su = getenv("SUDO_UID");
    const char* sg = getenv("SUDO_GID");
    if (su) { long v = strtol(su, nullptr, 10); if (v > 0) uid = (uid_t)v; }
    if (sg) { long v = strtol(sg, nullptr, 10); if (v > 0) gid = (gid_t)v; }
}

static void rm_workdir_contents(const std::string& host_ws) {
    int fd = open(host_ws.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;
    rm_contents_at(fd, 0);
}

// Hand the directory back to whoever invoked us, so the API can always remove
// it. This runs on EVERY exit path after the workspace was chowned, not only
// when --cleanup was requested: a multi-stage pipeline that aborts between
// stages (a failed compile, say) otherwise strands a directory owned by the
// sandbox uid that the unprivileged API user cannot delete.
static void restore_workdir_owner(const std::string& host_ws) {
    uid_t uid; gid_t gid;
    caller_ids(uid, gid);
    if (chown(host_ws.c_str(), uid, gid) < 0) { /* best effort */ }
    if (chmod(host_ws.c_str(), 0700) < 0)     { /* best effort */ }
}

// rmdir fails while tasks are still being reaped, so retry briefly.
static void cleanup_cgroup(const std::string& cgroup_path) {
    for (int i = 0; i < 50; ++i) {
        if (rmdir(cgroup_path.c_str()) == 0) return;
        if (errno != EBUSY) return;
        struct timespec ts{0, 2 * 1000 * 1000};  // 2ms
        nanosleep(&ts, nullptr);
    }
}

// ---------------------------------------------------------------------------
// Filesystem jail (runs in the leaf, still privileged)
// ---------------------------------------------------------------------------
static void mount_or_die(const char* src, const char* tgt, const char* fs,
                         unsigned long flags, const char* data, const char* what) {
    if (mount(src, tgt, fs, flags, data) < 0) die_child(what);
}

static void setup_filesystem_jail(const std::string& new_root,
                                  const std::string& workdir_rel,
                                  int tmp_mb) {
    // Detach our mount propagation from the host before touching anything.
    mount_or_die(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr,
                 "make / private");

    // Bind the rootfs onto itself so we can give it its own mount flags, then
    // remount it read-only. A read-only rootfs is what stops one run from
    // backdooring /usr/bin/python3 for every later run.
    mount_or_die(new_root.c_str(), new_root.c_str(), nullptr, MS_BIND | MS_REC,
                 nullptr, "bind rootfs");
    mount_or_die(nullptr, new_root.c_str(), nullptr,
                 MS_REMOUNT | MS_BIND | MS_REC | MS_RDONLY | MS_NOSUID | MS_NODEV,
                 nullptr, "remount rootfs ro");

    // The per-run workspace is the only writable part of the rootfs tree.
    if (!workdir_rel.empty()) {
        std::string ws = new_root + "/" + workdir_rel;
        mount_or_die(ws.c_str(), ws.c_str(), nullptr, MS_BIND, nullptr,
                     "bind workspace");
        mount_or_die(nullptr, ws.c_str(), nullptr,
                     MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV, nullptr,
                     "remount workspace rw");
    }

    // put_old must already exist: creating and removing it per run raced between
    // concurrent requests, because every run shares the same rootfs directory.
    std::string put_old = new_root + "/.old_root";
    struct stat st;
    if (stat(put_old.c_str(), &st) < 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr,
                "khoros(jail): %s missing; re-run scripts/bootstrap_rootfs.sh\n",
                put_old.c_str());
        _exit(126);
    }

    if (syscall(SYS_pivot_root, new_root.c_str(), put_old.c_str()) < 0)
        die_child("pivot_root");
    if (chdir("/") < 0) die_child("chdir /");
    if (umount2("/.old_root", MNT_DETACH) < 0) die_child("umount old root");

    mount_or_die("proc", "/proc", "proc",
                 MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr, "mount /proc");

    // Minimal /dev. Alpine's minirootfs ships an empty /dev, so without this
    // anything that opens /dev/null or /dev/urandom fails inside the jail.
    // MS_NODEV is deliberately absent here and only for this mount.
    mount_or_die("tmpfs", "/dev", "tmpfs", MS_NOSUID, "size=1m,mode=755",
                 "mount /dev");
    struct { const char* path; int maj; int min; } nodes[] = {
        {"/dev/null",    1, 3},
        {"/dev/zero",    1, 5},
        {"/dev/full",    1, 7},
        {"/dev/random",  1, 8},
        {"/dev/urandom", 1, 9},
    };
    for (auto& n : nodes) {
        if (mknod(n.path, S_IFCHR | 0666, makedev(n.maj, n.min)) < 0)
            die_child("mknod /dev node");
        if (chmod(n.path, 0666) < 0) die_child("chmod /dev node");
    }
    mount_or_die(nullptr, "/dev", nullptr,
                 MS_REMOUNT | MS_RDONLY | MS_NOSUID, "size=1m,mode=755",
                 "remount /dev ro");

    std::string tmp_opts = "size=" + std::to_string(tmp_mb) + "m,mode=1777";
    mount_or_die("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
                 tmp_opts.c_str(), "mount /tmp");
}

// ---------------------------------------------------------------------------
// Privilege drop (runs in the leaf, immediately before seccomp + execve)
// ---------------------------------------------------------------------------
static void drop_privileges(uid_t uid, gid_t gid) {
    if (uid == 0 || gid == 0) die_child("refusing to run sandboxed code as root");

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die_child("PR_SET_NO_NEW_PRIVS");

    // NOROOT means uid 0 is no longer special for capability grants, locked so
    // it cannot be undone. Must happen while we still hold CAP_SETPCAP.
    if (prctl(PR_SET_SECUREBITS, KH_SECUREBITS, 0, 0, 0) < 0)
        die_child("PR_SET_SECUREBITS");

    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    // Empty the bounding set so no capability can ever be regained, including
    // via a file-capability binary inside the rootfs.
    for (int cap = 0; cap <= 63; ++cap) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL)
            die_child("PR_CAPBSET_DROP");
    }

    if (setgroups(0, nullptr) < 0) die_child("setgroups");
    if (setresgid(gid, gid, gid) < 0) die_child("setresgid");
    if (setresuid(uid, uid, uid) < 0) die_child("setresuid");

    // Verify rather than trust: a silently failed drop is the whole ballgame.
    if (getuid() != uid || geteuid() != uid ||
        getgid() != gid || getegid() != gid)
        die_child("privilege drop did not take effect");
    if (setuid(0) == 0) {
        fprintf(stderr, "khoros(jail): regained uid 0 after drop; aborting\n");
        _exit(126);
    }

    // setuid() clears the dumpable flag, which makes /proc/self root-owned and
    // unreadable to us; some runtimes read /proc/self/status at startup.
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
}

static void apply_rlimits(int timeout_sec) {
    auto set = [](int res, rlim_t v, const char* what) {
        struct rlimit rl{v, v};
        if (setrlimit(res, &rl) < 0) die_child(what);
    };
    set(RLIMIT_CORE,   0, "RLIMIT_CORE");
    set(RLIMIT_FSIZE,  RLIMIT_FSIZE_BYTES, "RLIMIT_FSIZE");
    set(RLIMIT_NOFILE, RLIMIT_NOFILE_MAX,  "RLIMIT_NOFILE");
    // CPU-time backstop in case the wall-clock watchdog is ever defeated.
    set(RLIMIT_CPU,    static_cast<rlim_t>(timeout_sec) + 1, "RLIMIT_CPU");
}

// ---------------------------------------------------------------------------
// Seccomp
//
// This is an ALLOWLIST. The previous filter was default-allow with three denied
// syscalls, which left io_uring, bpf, the new mount API (fsopen/fsconfig/
// fsmount/move_mount/open_tree), module loading, keyctl, userfaultfd and
// perf_event_open all reachable. Default-deny means a syscall added by a future
// kernel is refused until it is deliberately allowed.
// ---------------------------------------------------------------------------
static const char* ALLOWED_SYSCALLS[] = {
    // file I/O
    "read", "write", "readv", "writev", "pread64", "pwrite64", "preadv",
    "pwritev", "open", "openat", "openat2", "close", "close_range", "creat",
    "lseek", "stat", "fstat", "lstat", "newfstatat", "statx", "access",
    "faccessat", "faccessat2", "readlink", "readlinkat", "getcwd", "chdir",
    "fchdir", "dup", "dup2", "dup3", "fcntl", "flock", "ioctl", "getdents",
    "getdents64", "statfs", "fstatfs", "fsync", "fdatasync", "truncate",
    "ftruncate", "sendfile", "copy_file_range", "splice", "tee",
    // file mutation inside the writable workspace and /tmp
    "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat", "rename", "renameat",
    "renameat2", "link", "linkat", "symlink", "symlinkat", "chmod", "fchmod",
    "fchmodat", "umask", "utimensat", "futimesat", "utimes",
    // memory
    "mmap", "mprotect", "munmap", "mremap", "msync", "brk", "madvise",
    "membarrier", "mincore",
    // process and thread lifecycle ("clone" is added separately, with an
    // argument filter, and "clone3" is given an explicit ENOSYS; see below)
    "fork", "vfork", "execve", "execveat", "wait4", "waitid", "exit",
    "exit_group", "kill", "tgkill", "tkill", "getpid", "gettid", "getppid",
    "getpgrp", "getpgid", "setpgid", "getsid", "setsid", "set_tid_address",
    "set_robust_list", "get_robust_list", "rseq", "sched_yield",
    "sched_getaffinity", "sched_setaffinity", "sched_getparam",
    "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
    // signals
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending",
    "rt_sigtimedwait", "rt_sigsuspend", "rt_sigqueueinfo", "sigaltstack",
    "pause", "restart_syscall",
    // synchronisation and polling
    "futex", "futex_waitv", "poll", "ppoll", "select", "pselect6",
    "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
    "eventfd", "eventfd2", "pipe", "pipe2",
    // time
    "clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep",
    "gettimeofday", "time", "times", "getitimer", "setitimer", "alarm",
    "timer_create", "timer_settime", "timer_gettime", "timer_delete",
    // identity and limits (read-only or self-scoped)
    "getuid", "geteuid", "getgid", "getegid", "getgroups", "getresuid",
    "getresgid", "getrlimit", "setrlimit", "prlimit64", "getrusage",
    "uname", "sysinfo", "getrandom", "arch_prctl", "prctl",
    // process_vm_readv/writev, ptrace, bpf, io_uring*, keyctl, mount*,
    // fsopen/fsconfig/fsmount/move_mount/open_tree, unshare, setns, chroot,
    // mknod*, init_module, finit_module, userfaultfd, perf_event_open,
    // socket, connect, bind, listen, sendto, recvfrom, socketpair, pidfd_getfd
    // and everything else are intentionally absent and return EPERM.
};

enum class SeccompMode { Enforce, Log, Off };

static void install_seccomp_filter(SeccompMode mode) {
    if (mode == SeccompMode::Off) return;

    uint32_t def = (mode == SeccompMode::Log) ? SCMP_ACT_LOG : SCMP_ACT_ERRNO(EPERM);
    scmp_filter_ctx ctx = seccomp_init(def);
    if (!ctx) die_child("seccomp_init");

    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 1);
    seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);

    for (const char* name : ALLOWED_SYSCALLS) {
        int nr = seccomp_syscall_resolve_name(name);
        if (nr == __NR_SCMP_ERROR) continue;   // unknown to this libseccomp
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0) < 0) {
            fprintf(stderr, "khoros(jail): seccomp_rule_add failed for %s\n", name);
            seccomp_release(ctx);
            _exit(126);
        }
    }

    // clone() is allowed only when it requests no new namespace, so threads and
    // ordinary fork-style clones pass while clone(CLONE_NEWNS|...) is refused.
    // There must be no unconditional rule for clone as well, or libseccomp
    // rejects this one as a conflict.
    const unsigned long ns_flags = CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID |
                                   CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC |
                                   CLONE_NEWCGROUP;
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
                         SCMP_A0(SCMP_CMP_MASKED_EQ, ns_flags, 0)) < 0) {
        fprintf(stderr, "khoros(jail): could not install clone filter\n");
        seccomp_release(ctx);
        _exit(126);
    }

    // clone3() passes its flags in a struct, which seccomp cannot inspect, so
    // it cannot be allowed safely. Returning ENOSYS rather than the default
    // EPERM makes glibc's pthread_create fall back to clone(); with EPERM it
    // reports "can't start new thread" instead. musl uses clone() directly, so
    // Alpine is unaffected either way, but this keeps a glibc rootfs working.
    int nr_clone3 = seccomp_syscall_resolve_name("clone3");
    if (nr_clone3 != __NR_SCMP_ERROR &&
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), nr_clone3, 0) < 0) {
        fprintf(stderr, "khoros(jail): warning: could not set clone3 fallback\n");
    }

    if (seccomp_load(ctx) < 0) {
        seccomp_release(ctx);
        die_child("seccomp_load");
    }
    seccomp_release(ctx);
}

// ---------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------
static void timeout_handler(int) {
    g_timed_out = 1;
    // Async-signal-safe only: the fd is pre-opened and we use write(2).
    if (g_kill_fd >= 0) {
        ssize_t r = write(g_kill_fd, "1\n", 2);
        (void)r;
    }
    if (g_child_pid > 0) kill(-g_child_pid, SIGKILL);
}

// ---------------------------------------------------------------------------
// Output capture: both streams drained concurrently with poll(), each capped.
//
// The previous version read stdout to EOF before touching stderr. A program
// writing more than one pipe buffer to stderr blocked forever, which showed up
// as a spurious timeout verdict.
// ---------------------------------------------------------------------------
struct Capture {
    std::string out, err;
    bool out_truncated = false, err_truncated = false;
};

static void capture_streams(int out_fd, int err_fd, Capture& cap) {
    struct pollfd fds[2];
    fds[0] = {out_fd, POLLIN, 0};
    fds[1] = {err_fd, POLLIN, 0};
    bool open_fds[2] = {true, true};
    std::string* bufs[2]  = {&cap.out, &cap.err};
    bool* trunc[2]        = {&cap.out_truncated, &cap.err_truncated};

    char buf[65536];
    while (open_fds[0] || open_fds[1]) {
        for (int i = 0; i < 2; ++i)
            fds[i].fd = open_fds[i] ? fds[i].fd : -1;

        int n = poll(fds, 2, 100);
        if (n < 0) {
            if (errno == EINTR) {
                if (g_timed_out) { /* keep draining until the pipes close */ }
                continue;
            }
            break;
        }

        for (int i = 0; i < 2; ++i) {
            if (!open_fds[i]) continue;
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;

            ssize_t r = read(fds[i].fd, buf, sizeof(buf));
            if (r > 0) {
                std::string& b = *bufs[i];
                if (b.size() < MAX_STREAM_BYTES) {
                    size_t room = MAX_STREAM_BYTES - b.size();
                    size_t take = std::min(room, static_cast<size_t>(r));
                    b.append(buf, take);
                    if (take < static_cast<size_t>(r)) *trunc[i] = true;
                } else {
                    // Keep reading and discarding so the child never blocks.
                    *trunc[i] = true;
                }
            } else if (r == 0) {
                open_fds[i] = false;
            } else if (errno != EINTR && errno != EAGAIN) {
                open_fds[i] = false;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal environment for the sandboxed process
// ---------------------------------------------------------------------------
static std::vector<char*> build_env(std::vector<std::string>& storage,
                                    const std::string& workdir_rel) {
    storage.push_back("PATH=/usr/local/bin:/usr/bin:/bin");
    storage.push_back("HOME=/tmp");
    storage.push_back("TMPDIR=/tmp");
    storage.push_back("LANG=C.UTF-8");
    storage.push_back("LC_ALL=C.UTF-8");
    storage.push_back("PYTHONDONTWRITEBYTECODE=1");
    storage.push_back("PYTHONUNBUFFERED=1");
    if (!workdir_rel.empty()) storage.push_back("PWD=/" + workdir_rel);

    std::vector<char*> envp;
    for (auto& s : storage) envp.push_back(const_cast<char*>(s.c_str()));
    envp.push_back(nullptr);
    return envp;
}

static void usage(const char* argv0) {
    fprintf(stderr,
        "Usage: %s [options] /absolute/path/to/cmd [args...]\n"
        "  --timeout <sec>    wall clock limit, %d-%d (default 2)\n"
        "  --mem <mb>         memory ceiling, %d-%d (default 64)\n"
        "  --pids <n>         max tasks, 1-%d (default 16)\n"
        "  --cpus <f>         CPU cores, e.g. 1.0 (default 1.0)\n"
        "  --tmp <mb>         size of the in-jail /tmp tmpfs (default 64)\n"
        "  --cgroup <id>      cgroup slice name, [A-Za-z0-9_-]{1,64}\n"
        "  --workdir <rel>    writable dir relative to rootfs, e.g. workspace/task_x\n"
        "  --cleanup          after the run, delete the workdir contents and\n"
        "                     return the empty dir to the calling user. Pass this\n"
        "                     only on the last stage of a multi-stage pipeline,\n"
        "                     otherwise it removes the compiler's output.\n"
        "  --uid <n>          unprivileged uid to run as (default %u)\n"
        "  --gid <n>          unprivileged gid to run as (default %u)\n"
        "  --seccomp <mode>   enforce | log | off (default enforce)\n",
        argv0, MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC, MIN_MEM_MB, MAX_MEM_MB,
        MAX_PIDS, DEFAULT_SANDBOX_UID, DEFAULT_SANDBOX_GID);
    _exit(2);
}

static int parse_int(const char* s, const char* what) {
    errno = 0;
    char* end = nullptr;
    long v = strtol(s, &end, 10);
    if (errno || !end || *end != '\0' || v < INT_MIN || v > INT_MAX) {
        fprintf(stderr, "khoros: invalid value for %s: %s\n", what, s);
        _exit(2);
    }
    return static_cast<int>(v);
}

static int clamp_int(int v, int lo, int hi, const char* what) {
    if (v < lo || v > hi) {
        fprintf(stderr, "khoros: %s must be between %d and %d (got %d)\n",
                what, lo, hi, v);
        _exit(2);
    }
    return v;
}

int main(int argc, char* argv[]) {
    int         timeout_sec = 2;
    int         mem_mb      = 64;
    int         pids_max    = 16;
    int         tmp_mb      = 64;
    double      cpus        = 1.0;
    std::string run_id      = "exec_default";
    std::string workdir_rel;
    uid_t       sandbox_uid = DEFAULT_SANDBOX_UID;
    gid_t       sandbox_gid = DEFAULT_SANDBOX_GID;
    SeccompMode seccomp_mode = SeccompMode::Enforce;
    bool        do_cleanup   = false;

    int i = 1;
    for (; i < argc; ) {
        auto need = [&](const char* flag) {
            if (i + 1 >= argc) {
                fprintf(stderr, "khoros: %s requires a value\n", flag);
                _exit(2);
            }
            return argv[i + 1];
        };
        if      (!strcmp(argv[i], "--timeout")) { timeout_sec = parse_int(need("--timeout"), "--timeout"); i += 2; }
        else if (!strcmp(argv[i], "--mem"))     { mem_mb      = parse_int(need("--mem"), "--mem"); i += 2; }
        else if (!strcmp(argv[i], "--pids"))    { pids_max    = parse_int(need("--pids"), "--pids"); i += 2; }
        else if (!strcmp(argv[i], "--tmp"))     { tmp_mb      = parse_int(need("--tmp"), "--tmp"); i += 2; }
        else if (!strcmp(argv[i], "--cpus"))    { cpus        = atof(need("--cpus")); i += 2; }
        else if (!strcmp(argv[i], "--cgroup"))  { run_id      = need("--cgroup"); i += 2; }
        else if (!strcmp(argv[i], "--workdir")) { workdir_rel = need("--workdir"); i += 2; }
        else if (!strcmp(argv[i], "--uid"))     { sandbox_uid = (uid_t)parse_int(need("--uid"), "--uid"); i += 2; }
        else if (!strcmp(argv[i], "--gid"))     { sandbox_gid = (gid_t)parse_int(need("--gid"), "--gid"); i += 2; }
        else if (!strcmp(argv[i], "--seccomp")) {
            const char* m = need("--seccomp");
            if      (!strcmp(m, "enforce")) seccomp_mode = SeccompMode::Enforce;
            else if (!strcmp(m, "log"))     seccomp_mode = SeccompMode::Log;
            else if (!strcmp(m, "off"))     seccomp_mode = SeccompMode::Off;
            else { fprintf(stderr, "khoros: bad --seccomp mode: %s\n", m); _exit(2); }
            i += 2;
        }
        else if (!strcmp(argv[i], "--cleanup")) { do_cleanup = true; i += 1; }
        else if (!strcmp(argv[i], "--help")) usage(argv[0]);
        else break;
    }

    if (i >= argc) usage(argv[0]);

    // Every client-supplied limit is validated here, not just forwarded. The
    // API previously passed timeout_sec straight from the request body, so
    // {"timeout_sec": 0} called alarm(0) and disabled the watchdog entirely.
    timeout_sec = clamp_int(timeout_sec, MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC, "--timeout");
    mem_mb      = clamp_int(mem_mb, MIN_MEM_MB, MAX_MEM_MB, "--mem");
    pids_max    = clamp_int(pids_max, 1, MAX_PIDS, "--pids");
    tmp_mb      = clamp_int(tmp_mb, 1, 512, "--tmp");
    if (!(cpus > 0.0 && cpus <= 8.0)) {
        fprintf(stderr, "khoros: --cpus must be in (0, 8]\n");
        _exit(2);
    }
    if (!valid_run_id(run_id)) {
        fprintf(stderr, "khoros: --cgroup must match [A-Za-z0-9_-]{1,64}\n");
        _exit(2);
    }
    if (!workdir_rel.empty() && !valid_rel_path(workdir_rel)) {
        fprintf(stderr, "khoros: --workdir must be a safe relative path\n");
        _exit(2);
    }
    if (argv[i][0] != '/') {
        fprintf(stderr, "khoros: command must be an absolute path (got %s)\n", argv[i]);
        _exit(2);
    }
    if (geteuid() != 0) {
        fprintf(stderr, "khoros: must run as root (the jail needs CAP_SYS_ADMIN)\n");
        _exit(2);
    }

    const int cmd_start = i;
    std::string rootfs = resolve_rootfs();
    ensure_parent_controllers();

    // Hand the workspace to the sandbox uid so the jailed, unprivileged process
    // can write its compiler output there, without the directory being 0777.
    if (!workdir_rel.empty()) {
        std::string host_ws = rootfs + "/" + workdir_rel;
        struct stat st;
        if (stat(host_ws.c_str(), &st) < 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "khoros: workdir %s does not exist\n", host_ws.c_str());
            _exit(2);
        }
        if (chown(host_ws.c_str(), sandbox_uid, sandbox_gid) < 0) die("chown workdir");
        if (chmod(host_ws.c_str(), 0700) < 0) die("chmod workdir");
        g_restore_ws = host_ws;   // every later exit path hands it back
    }

    int stdout_pipe[2], stderr_pipe[2], sync_pipe[2];
    if (pipe2(stdout_pipe, O_CLOEXEC) < 0 ||
        pipe2(stderr_pipe, O_CLOEXEC) < 0 ||
        pipe2(sync_pipe,   O_CLOEXEC) < 0) die("pipe2");

    auto start_time = std::chrono::steady_clock::now();

    pid_t child_pid = fork();
    if (child_pid < 0) die("fork");

    if (child_pid == 0) {
        // ---------------- middle child ----------------
        setpgid(0, 0);
        close(sync_pipe[1]);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0) _exit(126);
        if (dup2(stderr_pipe[1], STDERR_FILENO) < 0) _exit(126);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        // Wait until the parent has placed us in the cgroup. A short read or
        // EOF means the parent died before confining us, so refuse to run
        // rather than executing untrusted code without limits.
        char go = 0;
        if (read(sync_pipe[0], &go, 1) != 1 || go != 'G') _exit(126);
        close(sync_pipe[0]);

        if (unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC |
                    CLONE_NEWUTS | CLONE_NEWCGROUP) < 0) {
            fprintf(stderr, "khoros: unshare failed: %s\n", strerror(errno));
            _exit(126);
        }

        pid_t leaf = fork();   // becomes PID 1 of the new pid namespace
        if (leaf < 0) _exit(126);

        if (leaf == 0) {
            // ---------------- jailed leaf ----------------
            setup_filesystem_jail(rootfs, workdir_rel, tmp_mb);

            if (!workdir_rel.empty()) {
                std::string in_jail = "/" + workdir_rel;
                if (chdir(in_jail.c_str()) < 0) die_child("chdir workdir");
            }

            drop_privileges(sandbox_uid, sandbox_gid);
            apply_rlimits(timeout_sec);
            install_seccomp_filter(seccomp_mode);

            std::vector<char*> args;
            for (int k = cmd_start; k < argc; ++k) args.push_back(argv[k]);
            args.push_back(nullptr);

            std::vector<std::string> env_storage;
            std::vector<char*> envp = build_env(env_storage, workdir_rel);

            execve(args[0], args.data(), envp.data());
            die_child("execve");
        }

        int status = 0;
        if (waitpid(leaf, &status, 0) < 0) _exit(126);
        if (WIFEXITED(status))  _exit(WEXITSTATUS(status));
        if (WIFSIGNALED(status)) _exit(128 + WTERMSIG(status));
        _exit(126);
    }

    // ---------------- parent ----------------
    close(sync_pipe[0]);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    g_child_pid = child_pid;
    std::string cgroup_path = setup_cgroup(child_pid, run_id,
                                           {mem_mb, pids_max, cpus});

    // Pre-open cgroup.kill so the signal handler does no allocation.
    g_kill_fd = open((cgroup_path + "/cgroup.kill").c_str(), O_WRONLY | O_CLOEXEC);

    if (write(sync_pipe[1], "G", 1) != 1) die("sync write");
    close(sync_pipe[1]);

    // No SA_RESTART: we want poll() to return EINTR so the timeout is noticed
    // even if writing cgroup.kill fails.
    struct sigaction sa{};
    sa.sa_handler = timeout_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, nullptr) < 0) die("sigaction");
    alarm(static_cast<unsigned>(timeout_sec));

    Capture cap;
    capture_streams(stdout_pipe[0], stderr_pipe[0], cap);
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);

    int status = 0;
    while (waitpid(child_pid, &status, 0) < 0 && errno == EINTR) {}
    alarm(0);

    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start_time).count();

    unsigned long long peak_mem = read_peak_memory(cgroup_path);
    bool oom = was_oom_killed(cgroup_path);
    if (g_kill_fd >= 0) close(g_kill_fd);
    cleanup_cgroup(cgroup_path);

    if (!workdir_rel.empty()) {
        const std::string host_ws = rootfs + "/" + workdir_rel;
        if (do_cleanup) rm_workdir_contents(host_ws);
        restore_workdir_owner(host_ws);
        g_restore_ws.clear();
    }

    std::string verdict = "OK";
    int exit_code = 0;

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        exit_code = 128 + sig;
        if (oom)                 verdict = "MEMORY_LIMIT_EXCEEDED";
        else if (g_timed_out)    verdict = "TIME_LIMIT_EXCEEDED";
        else if (sig == SIGKILL) verdict = "KILLED";
        else                     verdict = "SIGNAL_TERMINATED";
    } else if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
        if (oom)                      verdict = "MEMORY_LIMIT_EXCEEDED";
        else if (g_timed_out)         verdict = "TIME_LIMIT_EXCEEDED";
        else if (exit_code == 126)    verdict = "SANDBOX_ERROR";
        else if (exit_code == 128 + SIGKILL) verdict = "KILLED";
        else if (exit_code != 0)      verdict = "NON_ZERO_EXIT";
    }

    printf("{\n");
    printf("  \"verdict\": \"%s\",\n", verdict.c_str());
    printf("  \"exit_code\": %d,\n", exit_code);
    printf("  \"wall_time_ms\": %lld,\n", static_cast<long long>(duration_ms));
    printf("  \"peak_memory_bytes\": %llu,\n", peak_mem);
    printf("  \"oom_killed\": %s,\n", oom ? "true" : "false");
    printf("  \"timed_out\": %s,\n", g_timed_out ? "true" : "false");
    printf("  \"stdout_truncated\": %s,\n", cap.out_truncated ? "true" : "false");
    printf("  \"stderr_truncated\": %s,\n", cap.err_truncated ? "true" : "false");
    printf("  \"stdout\": \"%s\",\n", escape_json(cap.out).c_str());
    printf("  \"stderr\": \"%s\"\n", escape_json(cap.err).c_str());
    printf("}\n");
    fflush(stdout);

    return 0;
}
