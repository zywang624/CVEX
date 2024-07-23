import argparse
import os
import io
import re
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path
import paramiko
import fabric
import vagrant
import yaml
import time
import logging

ROUTER_VM = "router"
ROUTER_CONFIG = {
    "image" : "bento/ubuntu-22.04",
    "destination" : "~/.cvex/router",
    "type" : "linux"
}

INIT_SNAPSHOT = "clean"
CVEX_SNAPSHOT = "cvex"

CVEX_TEMP_FOLDER_LINUX = "/tmp/cvex"
CVEX_TEMP_FOLDER_WINDOWS = "cvex"

MITMDUMP_LOG = "router_mitmdump.stream"
MITMDUMP_LOG_PATH = f"{CVEX_TEMP_FOLDER_LINUX}/{MITMDUMP_LOG}"
TCPDUMP_LOG = "router_raw.pcap"
TCPDUMP_LOG_PATH = f"{CVEX_TEMP_FOLDER_LINUX}/{TCPDUMP_LOG}"

log_level = logging.INFO

def get_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if log.hasHandlers():
        return log
    console_log_handler = logging.StreamHandler()
    console_log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - [%(name)s] %(message)s"))
    log.addHandler(console_log_handler)
    global log_level
    log.setLevel(log_level)
    return log


class SSH:
    log: logging.Logger
    ssh: fabric.Connection

    def __init__(self, vm: vagrant.Vagrant, vm_name: str):
        self.log = get_logger(vm_name)
        self.ssh = self._ssh_connect(vm)

    def _ssh_connect(self, vm: vagrant.Vagrant) -> fabric.Connection:
        self.log.debug("Retrieving SSH configuration...")
        hostname=vm.hostname()
        port=vm.port()
        username=vm.user()
        key_filename=vm.keyfile()
        self.log.debug("Connecting to %s:%d over SSH...", hostname, int(port))
        client = fabric.Connection(
            host=hostname, port=port, user=username, connect_kwargs={'key_filename': key_filename})
        return client

    def send_ctrl_c(self, runner: fabric.runners.Remote):
        message = paramiko.Message()
        message.add_byte(paramiko.common.cMSG_CHANNEL_REQUEST)
        message.add_int(runner.channel.remote_chanid)
        message.add_string("signal")
        message.add_boolean(False)
        message.add_string(signal.Signals.SIGTERM.name[3:])
        runner.channel.transport._send_user_message(message)

    def run_command(self, command: str, is_async: bool = False, until: str = "") -> str | tuple:
        self.log.info("Executing '%s'...", command)
        if is_async:
            result = self.ssh.run(command, asynchronous=is_async, hide=True)
            if until:
                while (not any(until in text for text in result.runner.stdout) and
                       not any(until in text for text in result.runner.stderr)):
                    time.sleep(0.1)
            return result.runner
        else:
            result = self.ssh.run(command, hide=True)
            if result.stdout:
                self.log.debug("Output:\n%s", result.stdout)
            return result.stdout

    def upload_file(self, local: str, dest: str):
        self.log.info("Uploading %s...", dest)
        self.ssh.put(local, dest)

    def download_file(self, local: str, dest: str):
        self.log.info("Downloading %s...", dest)
        self.ssh.get(dest, local)


private_ip = 1

class VM:
    log: logging.Logger
    vag: vagrant.Vagrant
    vm_name: str
    image: str
    destination: str
    vm_type: str
    playbook: str
    trace: str
    files: dict
    ip: str
    ssh: SSH

    def __init__(self, vm_name: str, config: dict):
        self.log = get_logger(vm_name)
        self.vag = vagrant.Vagrant(config['destination'])
        self.vm_name = vm_name
        self.image = config['image']
        self.destination = config['destination']
        self.vm_type = config['type']
        if 'playbook' in config:
            self.playbook = config['playbook']
        else:
            self.playbook = None
        if 'trace' in config:
            self.trace = config['trace']
        else:
            self.trace = None
        self.ip = None
    
    def _configure_vagrantfile(self):
        vagrantfile = os.path.join(self.destination, "Vagrantfile")
        if not os.path.exists(vagrantfile):
            self.log.critical("Can't find Vagrantfile %s", vagrantfile)
            sys.exit(1)
        with open(vagrantfile, "r") as f:
            data = f.read()
        config = f"  config.vm.box = \"{self.image}\""
        pos = data.find(config)
        if pos == -1:
            self.log.critical("Bad Vagrantfile %s", vagrantfile)
            sys.exit(1)
        with open(vagrantfile, "w") as f:
            f.write(data[:pos + len(config)])
            f.write((f"\n"
                     f"  config.vm.network \"private_network\", ip: \"{self.ip}\"\n"
                     f"  config.vm.hostname = \"{self.vm_name}\"\n"
                     f"\n"
                     ))
            f.write(data[pos + len(config):])
    
    def _generate_new_ip(self):
        global private_ip
        ip = f"192.168.56.{private_ip}"
        private_ip += 1
        return ip

    def _read_ip(self):
        vagrantfile = os.path.join(self.destination, "Vagrantfile")
        if not os.path.exists(vagrantfile):
            self.log.critical("Can't find Vagrantfile %s", vagrantfile)
            sys.exit(1)
        with open(vagrantfile, "r") as f:
            data = f.read()
        ip = re.search(r'config\.vm\.network "private_network", ip: "192\.168\.56\.(\d+)"', data)
        if not ip:
            self.log.critical("Bad Vagrantfile %s", vagrantfile)
            sys.exit(1)
        global private_ip
        private_ip = int(ip.group(1)) + 1
        return "192.168.56." + ip.group(1)

    def _init_router(self):
        self.log.info("Initializing the router VM")
        self.ssh.run_command("wget https://downloads.mitmproxy.org/10.3.1/mitmproxy-10.3.1-linux-x86_64.tar.gz")
        self.ssh.run_command("sudo tar -xf mitmproxy-10.3.1-linux-x86_64.tar.gz -C /usr/bin")

    def _run_shell_command(self, command: list[str], cwd: str | None = None) -> bytes:
        output = b""
        p = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd)
        for line in iter(p.stdout.readline, b''):
            output += line.rstrip()
        return output

    def _get_vagrant_winrm_config(self) -> dict:
        output = self._run_shell_command(["vagrant", "winrm-config"], cwd=self.destination)
        values = {
            "host" : rb"HostName (\d+\.\d+\.\d+\.\d+)",
            "user" : rb"User (\w+)",
            "password" : rb"Password (\w+)",
            "port" : rb"Port (\d+)"
        }
        config = {}
        for key, regexp in values.items():
            r = re.search(regexp, output)
            if not r:
                self.log.critical("'vagrant winrm-config' returned unusual output: %s", output)
                sys.exit(1)
            config[key] = r.group(1).decode()
        return config

    def _run_ansible(self):
        if not self.playbook:
            return
        inventory = os.path.join(self.destination, "inventory.ini")
        with open(inventory, "w") as f:
            if self.vm_type == "windows":
                self.log.info("Retrieving WinRM configuration of %s...", self.vm_name)
                config = self._get_vagrant_winrm_config()
                data = (f"{self.vm_name} "
                        f"ansible_connection=winrm "
                        f"ansible_winrm_scheme=http "
                        f"ansible_host={config['host']} "
                        f"ansible_port={config['port']} "
                        f"ansible_user={config['user']} "
                        f"ansible_password={config['password']}"
                        f"ansible_winrm_operation_timeout_sec=200  "
                        f"ansible_winrm_read_timeout_sec=210 "
                        f"operation_timeout_sec=250 "
                        f"read_timeout_sec=260")
            elif self.vm_type == "linux":
                self.log.info("Retrieving SSH configuration of %s...", self.vm_name)
                data = (f"{self.vm_name} "
                        f"ansible_host={self.vag.hostname()} "
                        f"ansible_port={self.vag.port()} "
                        f"ansible_user={self.vag.user()} "
                        f"ansible_ssh_private_key_file={self.vag.keyfile()} "
                        f"ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new'")
            f.write(data)
        self.log.info("Inventory %s has been created for VM %s", inventory, self.vm_name)
        self.log.info("Executing Ansible playbook %s for %s...", self.playbook, self.vm_name)
        #ansible_playbook_runner.Runner([inventory], self.playbook).run()
        self._run_shell_command(["ansible-playbook", "-i", inventory, self.playbook])

    def _provision_vm(self):
        self._run_ansible()
        if self.vm_name == ROUTER_VM:
            self._init_router()

    def _init_vm(self):
        self.log.info("Initializing a new VM %s at %s...", self.vm_name, self.destination)
        self.vag.init(box_url=self.image)
        self.ip = self._generate_new_ip()
        self._configure_vagrantfile()

    def _start_vm(self):
        self.log.info("Starting the VM %s...", self.vm_name)
        try:
            self.vag.up()
        except:
            self.log.critical("VM %s timed out. Please wait until the VM is started and then re-start CVEX.", self.vm_name)
            sys.exit(1)

        self.log.info("Creating snapshot %s for VM %s (%s)...", INIT_SNAPSHOT, self.vm_name, self.ip)
        self.vag.snapshot_save(INIT_SNAPSHOT)

        self.ssh = SSH(self.vag, self.vm_name)
        self._provision_vm()

        self.log.info("Creating snapshot %s for VM %s (%s)...", CVEX_SNAPSHOT, self.vm_name, self.ip)
        self.vag.snapshot_save(CVEX_SNAPSHOT)

    def run_vm(self):
        if not os.path.exists(self.destination):
            os.makedirs(self.destination)
            self._init_vm()
            self._start_vm()
            return
        
        self.log.info("Retrieving status of %s...", self.vm_name)
        status = self.vag.status()
 
        if status[0].state == "not_created":
            self._init_vm()
            self._start_vm()
        elif status[0].state == "running":
            self.ip = self._read_ip()
            self.log.info("VM %s (%s) is already running", self.vm_name, self.ip)
            self.ssh = SSH(self.vag, self.vm_name)

            self.log.info("Retrieving snapshot list of %s...", self.vm_name)
            snapshots = self.vag.snapshot_list()

            if INIT_SNAPSHOT not in snapshots:
                self.log.info("Creating snapshot %s for VM %s (%s)...", INIT_SNAPSHOT, self.vm_name, self.ip)
                self.vag.snapshot_save(INIT_SNAPSHOT)

            if CVEX_SNAPSHOT not in snapshots:
                self._provision_vm()
                self.log.info("Creating snapshot %s for VM %s (%s)...", CVEX_SNAPSHOT, self.vm_name, self.ip)
                self.vag.snapshot_save(CVEX_SNAPSHOT)
        else:
            self.log.info("Retrieving snapshot list of %s...", self.vm_name)
            snapshots = self.vag.snapshot_list()

            if CVEX_SNAPSHOT in snapshots:
                self.ip = self._read_ip()
                self.log.info("Restoring VM %s (%s) to snapshot %s...", self.vm_name, self.ip, CVEX_SNAPSHOT)
                self.vag.snapshot_restore(CVEX_SNAPSHOT)
                self.ssh = SSH(self.vag, self.vm_name)
            else:
                self._start_vm()

    def destroy(self):
        self.log.info("Destroying VM %s...", self.vm_name)
        try:
            self.vag.destroy()
            try:
                shutil.rmtree(self.destination)
            except:
                pass
        except:
            self.log.error("Failed")

    def stop(self):
        self.log.info("Stopping VM %s...", self.vm_name)
        try:
            self.vag.halt()
        except:
            self.log.error("Failed")


class Exploit:
    log: logging.Logger
    vms: dict

    def __init__(self, vms: dict):
        self.log = get_logger("Exploit")
        self.vms = vms

    def _read_output(self, runner: fabric.runners.Remote):
        try:
            stdouts = 0
            while True:
                if runner.program_finished.is_set():
                    self.log.info("DONE DONE DONE")
                    return
                new_stdouts = len(runner.stdout)
                if new_stdouts > stdouts:
                    for i in range(stdouts, new_stdouts):
                        self.log.debug(runner.stdout[i])
                stdouts = new_stdouts
                time.sleep(0.1)
        except:
            return

    def _get_windows_private_network_interface_index(self, vm: VM):
        route_print = vm.ssh.run_command("route print")
        id = re.search(r"(\d+)\.\.\.([0-9a-fA-F]{2} ){6}\.\.\.\.\.\.Intel\(R\) PRO/1000 MT Desktop Adapter #2", route_print)
        if not id:
            self.log.critical("'route print' returned unknown data:\n%s", route_print)
            sys.exit(1)
        return id.group(1)

    def _start_router_sniffing(self):
        if ROUTER_VM not in self.vms:
            return
        router = self.vms[ROUTER_VM]
        try:
            router.ssh.run_command("pkill mitmdump")
        except:
            pass
        try:
            router.ssh.run_command("sudo pkill tcpdump")
        except:
            pass
        try:
            router.ssh.run_command(f"rm -rf {CVEX_TEMP_FOLDER_LINUX}")
        except:
            pass
        router.ssh.run_command(f"mkdir {CVEX_TEMP_FOLDER_LINUX}")
        router.ssh.run_command("sudo sysctl net.ipv4.ip_forward=1")
        router.ssh.run_command("sudo iptables -t nat -I PREROUTING --src 0/0 --dst 0/0 -p tcp --dport 443 -j REDIRECT --to-ports 8080")
        router.tcpdump_runner = router.ssh.run_command(
            f"sudo tcpdump -i eth1 -U -w {TCPDUMP_LOG_PATH}", is_async=True)
        router.mitmdump_runner = router.ssh.run_command(
            f"mitmdump --mode transparent -k --set block_global=false -w {MITMDUMP_LOG_PATH}",
            is_async=True, until="Transparent Proxy listening at")
        router.mitmdump_thread = threading.Thread(target=self._read_output, args=[router.mitmdump_runner])
        router.mitmdump_thread.start()
        router.tcpdump_thread = threading.Thread(target=self._read_output, args=[router.tcpdump_runner])
        router.tcpdump_thread.start()

        for vm_name, vm in self.vms.items():
            if vm_name == ROUTER_VM:
                continue
            if vm.vm_type == "windows":
                vm.ssh.run_command("route DELETE 192.168.56.0")
                id = self._get_windows_private_network_interface_index(vm)
                vm.ssh.run_command(f"route ADD 192.168.56.0 MASK 255.255.255.0 {router.ip} if {id}")
            elif vm.vm_type == "linux":
                # TODO
                pass

    def _stop_router_sniffing(self, output_dir: str):
        if ROUTER_VM not in self.vms:
            return
        router = self.vms[ROUTER_VM]

        self.log.info("Wait for 5 seconds to let tcpdump flush log on disk...")
        time.sleep(5)
        # TODO: how to stop the processes?
        #router.ssh.send_ctrl_c(router.mitmdump_runner)
        #router.ssh.send_ctrl_c(router.tcpdump_runner)
        #router.mitmdump_thread.join()
        #router.tcpdump_thread.join()

        local = f"{output_dir}/{TCPDUMP_LOG}"
        router.ssh.download_file(local, TCPDUMP_LOG_PATH)
        self.log.info("tcpdump log was stored to %s", local)
        local = f"{output_dir}/{MITMDUMP_LOG}"
        router.ssh.download_file(local, MITMDUMP_LOG_PATH)
        self.log.info("mitmdump log was stored to %s", local)

    def _start_windows_api_tracing(self, vm: VM):
        return

    def _stop_windows_api_tracing(self, vm: VM, output_dir: str):
        return

    def _start_linux_api_tracing(self, vm: VM):
        vm.strace = {}
        try:
            vm.ssh.run_command("sudo pkill strace")
        except:
            pass
        try:
            vm.ssh.run_command(f"rm -rf {CVEX_TEMP_FOLDER_LINUX}")
        except:
            pass
        vm.ssh.run_command(f"mkdir {CVEX_TEMP_FOLDER_LINUX}")
        procs = vm.ssh.run_command(f"ps -ax | egrep \"{vm.trace}\" | grep -v grep")
        if not procs:
            self.log.critical("VM %s doesn't have processes that match '%s'", vm.vm_name, vm.trace)
            sys.exit(1)
        for pid, proc in re.findall(rf"(\d+).+? ({vm.trace})", procs):
            log = f"{CVEX_TEMP_FOLDER_LINUX}/{vm.vm_name}_strace_{proc}_{pid}.log"
            if log not in vm.strace:
                runner = vm.ssh.run_command(f"sudo strace -p {pid} -o {log}", is_async=True, until="attached")
                vm.strace[log] = runner

    def _stop_linux_api_tracing(self, vm: VM, output_dir: str):
        for _, runner in vm.strace.items():
            vm.ssh.send_ctrl_c(runner)
        for log, _ in vm.strace.items():
            out = f"{output_dir}/{log[len(CVEX_TEMP_FOLDER_LINUX)+1:]}"
            vm.ssh.download_file(out, log)
            self.log.info("strace log was stored to %s", out)

    def _start_api_tracing(self):
        for _, vm in self.vms.items():
            if vm.trace:
                if vm.vm_type == "windows":
                    self._start_windows_api_tracing(vm)
                elif vm.vm_type == "linux":
                    self._start_linux_api_tracing(vm)

    def _stop_api_tracing(self, output_dir: str):
        for _, vm in self.vms.items():
            if vm.trace:
                if vm.vm_type == "windows":
                    self._stop_windows_api_tracing(vm, output_dir)
                elif vm.vm_type == "linux":
                    self._stop_linux_api_tracing(vm, output_dir)

    def _get_command(self, command_template: str):
        command = command_template
        for vm_name, vm in self.vms.items():
            command = command.replace(f"%{vm_name}%", vm.ip)
        return command

    def run(self, attacker_vm: str, command: str, output_dir: str):
        self._start_router_sniffing()
        self._start_api_tracing()

        self.vms[attacker_vm].ssh.run_command(self._get_command(command))

        self._stop_router_sniffing(output_dir)
        self._stop_api_tracing(output_dir)


def verify_infrastructure_config(config: dict, config_path: str) -> dict | None:
    config_dir = os.path.split(config_path)[0]
    if 'vms' not in config or not config['vms']:
        return None
    if ROUTER_VM in config['vms']:
        return None
    for vm_name, data in config['vms'].items():
        if 'image' not in data or 'destination' not in data:
            return None
        config['vms'][vm_name]['destination'] = os.path.join(config_dir, data['destination'])
        if 'type' not in data or data['type'] not in ["linux", "windows"]:
            return None
        if 'playbook' in data:
            playbook = os.path.join(config_dir, data['playbook'])
            if not os.path.exists(playbook):
                return None
            config['vms'][vm_name]['playbook'] = playbook
    if 'exploit' not in config or 'vm' not in config['exploit'] or 'command' not in config['exploit']:
        return None
    if config['exploit']['vm'] not in config['vms']:
        return None
    return config


def main():
    parser = argparse.ArgumentParser(
        prog="cvex",
        description="",
    )
    parser.add_argument("-c", "--config", help="Configuration of the infrastructure", required=True, type=argparse.FileType('r'))
    parser.add_argument("-o", "--output", help="Directory for generated logs", default="logs")
    parser.add_argument("-d", "--destroy", help="Destroy VMs", default=False, action="store_true")
    parser.add_argument("-v", "--verbose", help="Verbose logs", default=False, action="store_true")
    args = parser.parse_args()

    if args.verbose:
        global log_level
        log_level = logging.DEBUG
    log = get_logger("main")

    output_dir = Path(args.output)
    if not output_dir.exists():
        output_dir.mkdir()
    elif not output_dir.is_dir():
        log.critical("%s is not a directory", output_dir)
        sys.exit(1)

    with args.config as f:
        infrastructure = yaml.safe_load(f)
    
    infrastructure = verify_infrastructure_config(infrastructure, args.config.name)
    if not infrastructure:
        log.critical("Configuration mismatch")
        sys.exit(1)

    if args.destroy:
        if len(infrastructure['vms']) > 1:
            ROUTER_CONFIG['destination'] = os.path.abspath(os.path.expanduser(ROUTER_CONFIG['destination']))
            vm = VM(ROUTER_VM, ROUTER_CONFIG)
            vm.destroy()
        for vm_name, config in infrastructure['vms'].items():
            vm = VM(vm_name, config)
            vm.destroy()
        sys.exit(0)

    vms = {}

    if len(infrastructure['vms']) > 1:
        ROUTER_CONFIG['destination'] = os.path.abspath(os.path.expanduser(ROUTER_CONFIG['destination']))
        vm = VM(ROUTER_VM, ROUTER_CONFIG)
        vm.run_vm()
        vms[ROUTER_VM] = vm
    for vm_name, config in infrastructure['vms'].items():
        vm = VM(vm_name, config)
        vm.run_vm()
        vms[vm_name] = vm

    exploit = Exploit(vms)
    exploit.run(infrastructure['exploit']['vm'], infrastructure['exploit']['command'], args.output)

    #for vm_name, vm in vms.items():
    #    vm.stop()

    sys.exit(0)

if __name__ == "__main__":
    main()
