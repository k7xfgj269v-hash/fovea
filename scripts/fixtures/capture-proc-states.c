// SPDX-License-Identifier: MIT
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *output_dir;

static int read_stat(pid_t pid, char *buffer, size_t size, char *state) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    ssize_t count = read(fd, buffer, size - 1);
    int saved = errno;
    close(fd);
    errno = saved;
    if (count <= 0) {
        return -1;
    }
    buffer[count] = '\0';
    char *close_paren = strrchr(buffer, ')');
    if (close_paren == NULL || close_paren[1] != ' ' ||
        close_paren[2] == '\0') {
        errno = EPROTO;
        return -1;
    }
    *state = close_paren[2];
    return 0;
}

static int wait_for_state(pid_t pid, char expected, char *buffer, size_t size) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    for (int attempt = 0; attempt < 5000; ++attempt) {
        char state = '\0';
        if (read_stat(pid, buffer, size, &state) == 0 && state == expected) {
            return 0;
        }
        nanosleep(&pause, NULL);
    }
    return -1;
}

static int write_capture(const char *file_name, const char *buffer) {
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/%s", output_dir, file_name) >=
        (int)sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) {
        return -1;
    }
    size_t length = strlen(buffer);
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, buffer + offset, length - offset);
        if (written < 0) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        offset += (size_t)written;
    }
    return close(fd);
}

static int emit(const char *label, const char *file_name, pid_t pid,
                char expected) {
    char buffer[8192];
    if (wait_for_state(pid, expected, buffer, sizeof(buffer)) != 0) {
        fprintf(stderr, "%s: did not observe state %c for pid %ld\n", label,
                expected, (long)pid);
        return -1;
    }
    if (write_capture(file_name, buffer) != 0) {
        perror(file_name);
        return -1;
    }
    printf("captured %s state=%c pid=%ld\n", file_name, expected, (long)pid);
    fflush(stdout);
    return 0;
}

static int capture_running(void) {
    char buffer[8192];
    for (int attempt = 0; attempt < 5000; ++attempt) {
        char state = '\0';
        if (read_stat(getpid(), buffer, sizeof(buffer), &state) == 0 &&
            state == 'R') {
            if (write_capture("stat-running.txt", buffer) != 0) {
                return -1;
            }
            printf("captured stat-running.txt state=R pid=%ld\n",
                   (long)getpid());
            return 0;
        }
    }
    return -1;
}

static int capture_sleeping(void) {
    pid_t child = fork();
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    if (child < 0) {
        return -1;
    }
    int result = emit("sleeping", "stat-sleeping.txt", child, 'S');
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return result;
}

static int vfork_child(void *unused) {
    (void)unused;
    sleep(2);
    return 0;
}

static int capture_disk_sleep(void) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return -1;
    }
    pid_t target = fork();
    if (target == 0) {
        close(pipefd[0]);
        pid_t self = getpid();
        if (write(pipefd[1], &self, sizeof(self)) != sizeof(self)) {
            _exit(2);
        }
        close(pipefd[1]);
        static char child_stack[1024 * 1024];
        pid_t child =
            clone(vfork_child, child_stack + sizeof(child_stack),
                  CLONE_VFORK | SIGCHLD, NULL);
        _exit(child < 0 ? 3 : 0);
    }
    close(pipefd[1]);
    pid_t announced = -1;
    ssize_t count = read(pipefd[0], &announced, sizeof(announced));
    close(pipefd[0]);
    if (target < 0 || count != sizeof(announced) || announced != target) {
        if (target > 0) {
            kill(target, SIGKILL);
            waitpid(target, NULL, 0);
        }
        return -1;
    }
    int result =
        emit("disk-sleep", "stat-disk-sleep.txt", target, 'D');
    waitpid(target, NULL, 0);
    return result;
}

static int capture_zombie(void) {
    pid_t child = fork();
    if (child == 0) {
        _exit(0);
    }
    if (child < 0) {
        return -1;
    }
    int result = emit("zombie", "stat-zombie.txt", child, 'Z');
    waitpid(child, NULL, 0);
    return result;
}

static int capture_stopped(void) {
    pid_t child = fork();
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    if (child < 0) {
        return -1;
    }
    kill(child, SIGSTOP);
    waitpid(child, NULL, WUNTRACED);
    int result = emit("stopped", "stat-stopped.txt", child, 'T');
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return result;
}

static int capture_tracing_stop(void) {
    pid_t child = fork();
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    if (child < 0) {
        return -1;
    }
    if (ptrace(PTRACE_ATTACH, child, NULL, NULL) != 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return -1;
    }
    waitpid(child, NULL, WUNTRACED);
    int result =
        emit("tracing-stop", "stat-tracing-stop.txt", child, 't');
    ptrace(PTRACE_DETACH, child, NULL, NULL);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return result;
}

static int capture_idle(void) {
    DIR *proc = opendir("/proc");
    if (proc == NULL) {
        return -1;
    }
    int result = -1;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        char *end = NULL;
        long value = strtol(entry->d_name, &end, 10);
        if (entry->d_name[0] == '\0' || *end != '\0' || value <= 0) {
            continue;
        }
        char buffer[8192];
        char state = '\0';
        if (read_stat((pid_t)value, buffer, sizeof(buffer), &state) == 0 &&
            state == 'I') {
            if (write_capture("stat-idle.txt", buffer) != 0) {
                closedir(proc);
                return -1;
            }
            printf("captured stat-idle.txt state=I pid=%ld\n", value);
            result = 0;
            break;
        }
    }
    closedir(proc);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s OUTPUT_DIR\n", argv[0]);
        return 2;
    }
    output_dir = argv[1];
    int failed = 0;
    failed |= capture_running() != 0;
    failed |= capture_sleeping() != 0;
    failed |= capture_disk_sleep() != 0;
    failed |= capture_zombie() != 0;
    failed |= capture_stopped() != 0;
    failed |= capture_tracing_stop() != 0;
    failed |= capture_idle() != 0;
    return failed ? 1 : 0;
}
