#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <seccomp.h>
#include <chrono>

pid_t g_child_pid = -1;
std::string g_run_id = "exec_default";

std::string escape_json(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        switch (c) {
            case '"':  ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b";  break;
            case '\f': ss << "\\f";  break;
            case '\n': ss << "\\n";  break;
            case '\r': ss << "\\r";  break;
            case '\t': ss << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    ss << buf;
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

void timeout_handler(int sig) {
    if (g_child_pid > 0) {
        std::ofstream killer("/sys/fs/cgroup/sandbox_demo/" + g_run_id + "/cgroup.kill");
        if (killer.is_open()) {
            killer << "1\n";
            killer.close();
        }
        kill(-g_child_pid, SIGKILL);
        kill(g_child_pid, SIGKILL);
    }
}

bool setup_cgroup(pid_t pid, const std::string& run_id, int mem_mb) {
    std::string base_path = "/sys/fs/cgroup/sandbox_demo/" + run_id;
    mkdir(base_path.c_str(), 0755);

    std::ofstream swap_file(base_path + "/memory.swap.max");
    if (swap_file.is_open()) swap_file << "0\n";

    std::ofstream mem_file(base_path + "/memory.max");
    if (!mem_file.is_open()) return false;
    mem_file << (static_cast<long long>(mem_mb) * 1024 * 1024) << "\n";

    std::ofstream pids_file(base_path + "/pids.max");
    if (!pids_file.is_open()) return false;
    pids_file << "16\n";

    std::ofstream procs_file(base_path + "/cgroup.procs");
    if (!procs_file.is_open()) return false;
    procs_file << pid << "\n";

    return true;
}

unsigned long long get_peak_memory(const std::string& run_id) {
    std::string peak_path = "/sys/fs/cgroup/sandbox_demo/" + run_id + "/memory.peak";
    std::ifstream peak_file(peak_path);
    if (peak_file.is_open()) {
        std::string bytes;
        peak_file >> bytes;
        try {
            return std::stoull(bytes);
        } catch (...) {}
    }
    return 0;
}

void cleanup_cgroup(const std::string& run_id) {
    std::string base_path = "/sys/fs/cgroup/sandbox_demo/" + run_id;
    rmdir(base_path.c_str());
}

bool setup_filesystem_jail(const char* new_root) {
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) return false;
    if (mount(new_root, new_root, nullptr, MS_BIND | MS_REC, nullptr) < 0) return false;

    std::string put_old = std::string(new_root) + "/.old_root";
    mkdir(put_old.c_str(), 0700);

    if (syscall(SYS_pivot_root, new_root, put_old.c_str()) < 0) return false;
    if (chdir("/") < 0) return false;

    if (umount2("/.old_root", MNT_DETACH) < 0) return false;
    rmdir("/.old_root");

    mkdir("/proc", 0755);
    mount("proc", "/proc", "proc", 0, nullptr);

    mkdir("/tmp", 0777);
    mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=64m");

    return true;
}

bool install_seccomp_filter() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return false;

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) return false;

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(connect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);

    if (seccomp_load(ctx) < 0) {
        seccomp_release(ctx);
        return false;
    }

    seccomp_release(ctx);
    return true;
}

int main(int argc, char* argv[]) {
    int timeout_sec = 2;
    int mem_mb = 64;
    std::string run_id = "exec_default";
    int cmd_start = 1;

    while (cmd_start < argc) {
        if (strcmp(argv[cmd_start], "--timeout") == 0 && cmd_start + 1 < argc) {
            timeout_sec = atoi(argv[cmd_start + 1]);
            cmd_start += 2;
        } else if (strcmp(argv[cmd_start], "--mem") == 0 && cmd_start + 1 < argc) {
            mem_mb = atoi(argv[cmd_start + 1]);
            cmd_start += 2;
        } else if (strcmp(argv[cmd_start], "--cgroup") == 0 && cmd_start + 1 < argc) {
            run_id = argv[cmd_start + 1];
            cmd_start += 2;
        } else {
            break;
        }
    }

    g_run_id = run_id;

    if (cmd_start >= argc) {
        std::cerr << "Usage: " << argv[0] << " [--timeout <sec>] [--mem <mb>] [--cgroup <id>] <cmd> [args...]\n";
        return 1;
    }

    char resolved_rootfs[PATH_MAX];
    if (!realpath("./rootfs", resolved_rootfs)) {
        perror("realpath ./rootfs failed");
        return 1;
    }

    int stdout_pipe[2];
    int stderr_pipe[2];
    int sync_pipe[2];

    if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0 || pipe(sync_pipe) < 0) {
        perror("pipe failed");
        return 1;
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    pid_t child_pid = fork();

    if (child_pid < 0) {
        perror("fork failed");
        return 1;
    }

    if (child_pid == 0) {
        setpgid(0, 0);

        close(sync_pipe[1]);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        char sync_buf;
        if (read(sync_pipe[0], &sync_buf, 1) < 0) return 1;
        close(sync_pipe[0]);

        if (unshare(CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWNS) < 0) return 1;

        pid_t jailed_pid = fork();
        if (jailed_pid < 0) return 1;

        if (jailed_pid == 0) {
            if (!setup_filesystem_jail(resolved_rootfs)) return 1;
            if (!install_seccomp_filter()) return 1;

            std::vector<char*> args;
            for (int i = cmd_start; i < argc; ++i) args.push_back(argv[i]);
            args.push_back(nullptr);

            execvp(args[0], args.data());
            return 1;
        }

        int status;
        waitpid(jailed_pid, &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : (128 + WTERMSIG(status));
    }

    close(sync_pipe[0]);
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    g_child_pid = child_pid;
    setup_cgroup(child_pid, g_run_id, mem_mb);

    write(sync_pipe[1], "GO", 1);
    close(sync_pipe[1]);

    signal(SIGALRM, timeout_handler);
    alarm(timeout_sec);

    std::string captured_stdout, captured_stderr;
    char buffer[4096];
    ssize_t bytes_read;

    while ((bytes_read = read(stdout_pipe[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        captured_stdout += buffer;
    }
    while ((bytes_read = read(stderr_pipe[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        captured_stderr += buffer;
    }
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);

    int status;
    waitpid(child_pid, &status, 0);
    alarm(0);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    unsigned long long peak_mem = get_peak_memory(g_run_id);
    cleanup_cgroup(g_run_id);

    std::string verdict = "OK";
    int exit_code = 0;

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGKILL) verdict = "TIME_OR_MEMORY_LIMIT_EXCEEDED";
        else verdict = "SIGNAL_TERMINATED";
        exit_code = 128 + sig;
    } else if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
        if (exit_code == 137 || exit_code == (128 + SIGKILL)) {
            verdict = "TIME_OR_MEMORY_LIMIT_EXCEEDED";
        } else if (exit_code != 0) {
            verdict = "NON_ZERO_EXIT";
        }
    }

    std::cout << "{\n";
    std::cout << "  \"verdict\": \"" << verdict << "\",\n";
    std::cout << "  \"exit_code\": " << exit_code << ",\n";
    std::cout << "  \"wall_time_ms\": " << duration_ms << ",\n";
    std::cout << "  \"peak_memory_bytes\": " << peak_mem << ",\n";
    std::cout << "  \"stdout\": \"" << escape_json(captured_stdout) << "\",\n";
    std::cout << "  \"stderr\": \"" << escape_json(captured_stderr) << "\"\n";
    std::cout << "}\n";

    return 0;
}