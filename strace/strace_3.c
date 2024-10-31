#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <errno.h>

const char *syscall_names[] = {
    "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek",
    "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
    "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", 
    // Add more syscalls as needed
};

void print_hex(void *addr, size_t size) {
    unsigned char *byte = (unsigned char *)addr;
    for (size_t i = 0; i < size; i++) {
        printf("%02x", byte[i]);
        if (i < size - 1) {
            printf(", ");
        }
    }
}

void trace_process(pid_t child) {
    struct user_regs_struct regs;
    int status;

    while (1) {
        waitpid(child, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        if (WIFSTOPPED(status) && (status >> 8) == SIGTRAP) {
            // Get syscall number
            long syscall_num = regs.orig_rax;
            printf("%s(", syscall_names[syscall_num]);

            // Depending on the syscall, you might want to print different arguments
            // For now, we will print only the first argument as an example
            printf("0x%llx", regs.rdi); // First argument in rdi
            printf(", 0x%llx", regs.rsi); // Second argument in rsi
            printf(", ..."); // Indicate more arguments are present
            printf(")\n");

            // Execute the syscall
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);
            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            // Get return value
            long ret_val = regs.rax;
            printf(" = 0x%llx\n", ret_val);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s command [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();
    if (child == 0) {
        // Child process: allow tracing and exec the command
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
        perror("execvp failed");
        return 1;
    } else {
        // Parent process: trace the child
        trace_process(child);
    }

    return 0;
}
