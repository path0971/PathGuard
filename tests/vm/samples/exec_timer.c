/* exec_timer FILE...
 * fork+execs each file once (stdout/stderr to /dev/null) and prints latency
 * statistics in microseconds. Each file is used once so a test can control
 * whether the agent sees it for the first time (scan) or again (cache). */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int cmp(const void* a, const void* b) {
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

int main(int argc, char** argv) {
    int n = argc - 1, failures = 0;
    if (n <= 0) {
        fprintf(stderr, "usage: exec_timer FILE...\n");
        return 2;
    }
    double* lat = calloc((size_t)n, sizeof *lat);
    double sum = 0;
    for (int i = 0; i < n; ++i) {
        double t0 = now_us();
        pid_t pid = fork();
        if (pid == 0) {
            int dn = open("/dev/null", O_WRONLY);
            dup2(dn, 1);
            dup2(dn, 2);
            char* args[] = {argv[i + 1], NULL};
            execv(argv[i + 1], args);
            _exit(127);
        }
        int st = 0;
        waitpid(pid, &st, 0);
        lat[i] = now_us() - t0;
        sum += lat[i];
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) ++failures;
    }
    qsort(lat, (size_t)n, sizeof *lat, cmp);
    printf("count=%d failures=%d p50_us=%.0f p95_us=%.0f mean_us=%.0f max_us=%.0f\n", n, failures,
           lat[(n - 1) * 50 / 100], lat[(n - 1) * 95 / 100], sum / n, lat[n - 1]);
    free(lat);
    return 0;
}
