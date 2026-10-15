/* Numeric PID/TID lookup and fd-relative procfs regression probe. */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check_pid(const char *path, pid_t expected) {
    FILE *file = fopen(path, "r");
    if (!file) { perror(path); exit(2); }
    char line[512]; int found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (!strncmp(line, "NSpid:", 6)) {
            char *cursor = line + 6, *end; long inner = -1;
            while (*cursor) {
                long value = strtol(cursor, &end, 10);
                if (cursor == end) break;
                inner = value; cursor = end;
            }
            if (inner != expected) { fprintf(stderr, "%s: expected %d, got %ld\n", path, expected, inner); exit(3); }
            found = 1; break;
        }
    }
    fclose(file); assert(found);
}
static void *thread_check(void *unused) {
    (void)unused;
    pid_t tid = syscall(SYS_gettid); char path[128];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/status", getpid(), tid);
    check_pid(path, tid);
    snprintf(path, sizeof(path), "/proc/%d/status", tid);
    check_pid(path, tid);
    return NULL;
}
static char survivor_pid[32], survivor_pipe[32];
static void *thread_exec(void *unused) {
    thread_check(unused);
    execl("/proc/self/exe", "proc-lookup-probe", "thread-exec-check",
          survivor_pid, survivor_pipe, (char *)NULL);
    perror("exec from non-leader thread");
    _exit(5);
}
static int worker_pipe[2];
static pthread_barrier_t worker_ready;
static void *idle_worker(void *unused) {
    (void)unused;
    pthread_barrier_wait(&worker_ready);
    char byte;
    assert(read(worker_pipe[0], &byte, 1) == 0);
    return NULL;
}
static void checks(void) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/status", getpid()); check_pid(path, getpid());
    check_pid("/proc/self/status", getpid());
    pthread_t threads[2];
    for (int i=0;i<2;i++) assert(!pthread_create(&threads[i], NULL, thread_check, NULL));
    for (int i=0;i<2;i++) assert(!pthread_join(threads[i], NULL));
    for (int i=0;i<16;i++) {
        int descriptors[2]; assert(!pipe(descriptors));
        pid_t parent = getpid(); pid_t child=fork(); assert(child>=0);
        if (!child) {
            close(descriptors[1]);
            snprintf(path,sizeof(path),"/proc/%d/status",parent); check_pid(path,parent);
            snprintf(path,sizeof(path),"/proc/%d/status",getpid());check_pid(path,getpid());
            char byte; assert(read(descriptors[0],&byte,1)==1);_exit(0);
        }
        close(descriptors[0]);
        snprintf(path,sizeof(path),"/proc/%d/status",child);check_pid(path,child);
        assert(write(descriptors[1],"x",1)==1);close(descriptors[1]);
        int status;assert(waitpid(child,&status,0)==child);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    }
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        check_pid("/proc/self/status", getpid());
        int ready[2]; assert(!pipe(ready));
        pid_t survivor = fork(); assert(survivor >= 0);
        if (!survivor) {
            close(ready[1]);
            char byte; assert(read(ready[0], &byte, 1) == 1);
            _exit(7);
        }
        close(ready[0]);
        snprintf(path, sizeof(path), "/proc/%d/status", survivor);
        check_pid(path, survivor);
        snprintf(survivor_pid, sizeof(survivor_pid), "%d", survivor);
        snprintf(survivor_pipe, sizeof(survivor_pipe), "%d", ready[1]);
        pthread_t thread;
        assert(!pthread_create(&thread, NULL, thread_exec, NULL));
        pthread_join(thread, NULL);
        _exit(6);
    }
    int status; assert(waitpid(child, &status, 0) == child);
    if (!WIFEXITED(status) || WEXITSTATUS(status))
        fprintf(stderr, "non-leader exec child wait status: %d\n", status);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "thread-exec-check")) {
        char path[128];
        assert(getpid() == syscall(SYS_gettid));
        snprintf(path, sizeof(path), "/proc/%d/status", getpid());
        check_pid(path, getpid());
        check_pid("/proc/self/status", getpid());
        pid_t survivor = atoi(argv[2]); int descriptor = atoi(argv[3]);
        snprintf(path, sizeof(path), "/proc/%d/status", survivor);
        check_pid(path, survivor);
        assert(write(descriptor, "x", 1) == 1); close(descriptor);
        int status; assert(waitpid(survivor, &status, 0) == survivor);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
        return 0;
    }
    int iterations=argc>1?atoi(argv[1]):40;
    int workers = argc > 3 ? atoi(argv[3]) : 0;
    int check = argc > 2 && !strcmp(argv[2], "check");
    if (iterations < 1 || iterations > 1000000 || argc > 4 || workers < 0 || workers > 128
        || (argc > 2 && !check && strcmp(argv[2], "bench"))) return 2;
    if (check) checks();
    pthread_t threads[128];
    if (workers) {
        assert(!pipe(worker_pipe));
        assert(!pthread_barrier_init(&worker_ready, NULL, workers + 1));
        for (int i = 0; i < workers; i++) assert(!pthread_create(&threads[i], NULL, idle_worker, NULL));
        pthread_barrier_wait(&worker_ready);
    }
    int descriptor=open("/proc/self/fdinfo",O_RDONLY|O_DIRECTORY);assert(descriptor>=0);
    struct timespec start,end;clock_gettime(CLOCK_MONOTONIC,&start);
    for(int i=0;i<iterations;i++) {
        int fd=openat(descriptor,"0",O_RDONLY);if(fd<0){perror("fdinfo");return 4;}
        char buffer[128];assert(read(fd,buffer,sizeof(buffer))>0);close(fd);
    }
    clock_gettime(CLOCK_MONOTONIC,&end);close(descriptor);
    double seconds=end.tv_sec-start.tv_sec+(end.tv_nsec-start.tv_nsec)/1e9;
    if (workers) {
        close(worker_pipe[1]);
        for (int i = 0; i < workers; i++) assert(!pthread_join(threads[i], NULL));
        close(worker_pipe[0]);
        pthread_barrier_destroy(&worker_ready);
    }
    printf("{\"iterations\":%d,\"workers\":%d,\"seconds\":%.9f,\"checks\":%s}\n",iterations,workers,seconds,check?"true":"false");
    return 0;
}
