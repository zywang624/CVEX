import re
import subprocess
import sys
import time
import os

process_name_re = sys.argv[1]
out_folder = sys.argv[2]
vm_name = sys.argv[3]

procs = {}
print("Agent started")

while True:
    while True:
        output = subprocess.Popen(f"ps -ax | egrep \"{process_name_re}\" | grep -v grep",
                                  shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in iter(output.stdout.readline, b''):
            r = re.search(rf"(\d+).+? ({process_name_re})".encode(), line)
            if r:
                pid = r.group(1).decode()
                process_name = r.group(2).decode()
                if int(pid) != os.getpid():
                    if pid not in procs:
                        log = f"{out_folder}/{vm_name}_strace_{process_name}_{pid}.log"
                        procs[pid] = subprocess.Popen(f"sudo strace -p {pid} -o {log} -v", shell=True)
        time.sleep(1)


