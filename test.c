#include <unistd.h>
#include <stdio.h>

int main() {
    char *env[] = {"SHELL=/bin/bash", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
    char *args[] = {NULL};

    execve("/usr/bin/pkexec", args, env);
    return 0;
}