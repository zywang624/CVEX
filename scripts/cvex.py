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

MITMDUMP_LOG = "mitmdump.stream"
MITMDUMP_LOG_PATH = f"{CVEX_TEMP_FOLDER_LINUX}/{MITMDUMP_LOG}"
TCPDUMP_LOG = "raw.pcap"
TCPDUMP_LOG_PATH = f"{CVEX_TEMP_FOLDER_LINUX}/{TCPDUMP_LOG}"

class SSH:
    ssh: fabric.Connection

    def __init__(self, vm: vagrant.Vagrant):
        self.ssh = self._ssh_connect(vm)

    def _ssh_connect(self, vm: vagrant.Vagrant) -> fabric.Connection:
        print(f"Retrieving SSH configuration...")
        hostname=vm.hostname()
        port=vm.port()
        username=vm.user()
        key_filename=vm.keyfile()
        print("Done")
        print(f"Connecting to {hostname}:{port} over SSH...")
        client = fabric.Connection(
            host=hostname, port=port, user=username, connect_kwargs={'key_filename': key_filename})
        print("Done")
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
        print(f"Executing '{command}'...")
        if is_async:
            result = self.ssh.run(command, asynchronous=is_async)
            if until:
                while not any(until in text for text in result.runner.stdout):
                    time.sleep(0.1)
            return result.runner
        else:
            result = self.ssh.run(command)
            print(result.stdout)
            return result.stdout

    def upload_file(self, local: str, dest: str):
        print(f"Uploading '{dest}'...")
        self.ssh.put(local, dest)
        print("Done")

    def download_file(self, local: str, dest: str):
        print(f"Downloading '{dest}'...")
        self.ssh.get(dest, local)
        print("Done")


private_ip = 1

class VM:
    vag: vagrant.Vagrant
    vm_name: str
    image: str
    destination: str
    vm_type: str
    playbook: str
    files: dict
    ip: str
    ssh: SSH

    def __init__(self, vm_name: str, config: dict):
        self.vag = vagrant.Vagrant(config['destination'])
        self.vm_name = vm_name
        self.image = config['image']
        self.destination = config['destination']
        self.vm_type = config['type']
        if 'playbook' in config:
            self.playbook = config['playbook']
        else:
            self.playbook = None
        self.ip = None
    
    def _configure_vagrantfile(self):
        vagrantfile = os.path.join(self.destination, "Vagrantfile")
        if not os.path.exists(vagrantfile):
            print(f"Can't find Vagrantfile '{vagrantfile}'")
            sys.exit(1)
        with open(vagrantfile, "r") as f:
            data = f.read()
        config = f"  config.vm.box = \"{self.image}\""
        pos = data.find(config)
        if pos == -1:
            print(f"Bad Vagrantfile")
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
            print(f"Can't find Vagrantfile '{vagrantfile}'")
            sys.exit(1)
        with open(vagrantfile, "r") as f:
            data = f.read()
        ip = re.search(r'config\.vm\.network "private_network", ip: "192\.168\.56\.(\d+)"', data)
        if not ip:
            print(f"Bad Vagrantfile")
            sys.exit(1)
        global private_ip
        private_ip = int(ip.group(1)) + 1
        return "192.168.56." + ip.group(1)

    def _init_router(self):
        print("Initializing the router VM")
        print("Downloading mitmproxy...")
        self.ssh.run_command("wget https://downloads.mitmproxy.org/10.3.1/mitmproxy-10.3.1-linux-x86_64.tar.gz")
        print("Done")
        print("Unpacking mitmproxy...")
        self.ssh.run_command("sudo tar -xf mitmproxy-10.3.1-linux-x86_64.tar.gz -C /usr/bin")
        print("Done")

    def _run_shell_command(self, command: list[str], cwd: str | None = None) -> bytes:
        output = b""
        p = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd)
        for line in iter(p.stdout.readline, b''):
            print(line)
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
                print(f"'vagrant winrm-config' returned unusual output: {output}")
                sys.exit(1)
            config[key] = r.group(1).decode()
        return config

    def _run_ansible(self):
        if not self.playbook:
            return
        inventory = os.path.join(self.destination, "inventory.ini")
        with open(inventory, "w") as f:
            if self.vm_type == "windows":
                print(f"Retrieving WinRM configuration of '{self.vm_name}'...")
                config = self._get_vagrant_winrm_config()
                print("Done")
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
                print(f"Retrieving SSH configuration of '{self.vm_name}'...")
                data = (f"{self.vm_name} "
                        f"ansible_host={self.vag.hostname()} "
                        f"ansible_port={self.vag.port()} "
                        f"ansible_user={self.vag.user()} "
                        f"ansible_ssh_private_key_file={self.vag.keyfile()} "
                        f"ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new'")
                print("Done")
            f.write(data)
        print(f"Inventory '{inventory}' has been created for VM '{self.vm_name}'")
        print(f"Executing Ansible playbook '{self.playbook}' for '{self.vm_name}'...")
        #ansible_playbook_runner.Runner([inventory], self.playbook).run()
        self._run_shell_command(["ansible-playbook", "-i", inventory, self.playbook])
        print("Done")

    def _provision_vm(self):
        self._run_ansible()
        if self.vm_name == ROUTER_VM:
            self._init_router()

    def _init_vm(self):
        print(f"Initializing a new VM '{self.vm_name}' at '{self.destination}'...")
        self.vag.init(box_url=self.image)
        print("Done")
        self.ip = self._generate_new_ip()
        self._configure_vagrantfile()

    def _start_vm(self):
        print(f"Starting the VM '{self.vm_name}'...")
        try:
            self.vag.up()
        except:
            print(f"VM '{self.vm_name}' timed out. Please wait until the VM is started and then re-start CVEX.")
            sys.exit(1)
        print("Done")
        
        print(f"Creating snapshot '{INIT_SNAPSHOT}' for VM '{self.vm_name}' ({self.ip})...")
        self.vag.snapshot_save(INIT_SNAPSHOT)
        print("Done")
        
        self.ssh = SSH(self.vag)
        self._provision_vm()

        print(f"Creating snapshot '{CVEX_SNAPSHOT}' for VM '{self.vm_name}' ({self.ip})...")
        self.vag.snapshot_save(CVEX_SNAPSHOT)
        print("Done")

    def run_vm(self):
        if not os.path.exists(self.destination):
            os.makedirs(self.destination)
            self._init_vm()
            self._start_vm()
            return
        
        print(f"Retrieving status of '{self.vm_name}'...")
        status = self.vag.status()
 
        if status[0].state == "not_created":
            self._init_vm()
            self._start_vm()
        elif status[0].state == "running":
            self.ip = self._read_ip()
            print(f"VM '{self.vm_name}' ({self.ip}) is already running")
            self.ssh = SSH(self.vag)

            print(f"Retrieving snapshot list of '{self.vm_name}'...")
            snapshots = self.vag.snapshot_list()
            print("Done")

            if INIT_SNAPSHOT not in snapshots:
                print(f"Creating snapshot '{INIT_SNAPSHOT}' for VM '{self.vm_name}' ({self.ip})...")
                self.vag.snapshot_save(INIT_SNAPSHOT)
                print("Done")

            if CVEX_SNAPSHOT not in snapshots:
                self._provision_vm()
                print(f"Creating snapshot '{CVEX_SNAPSHOT}' for VM '{self.vm_name}' ({self.ip})...")
                self.vag.snapshot_save(CVEX_SNAPSHOT)
                print("Done")
        else:
            print(f"Retrieving snapshot list of '{self.vm_name}'...")
            snapshots = self.vag.snapshot_list()
            print("Done")

            if CVEX_SNAPSHOT in snapshots:
                self.ip = self._read_ip()
                print(f"Restoring VM '{self.vm_name}' ({self.ip}) to snapshot '{CVEX_SNAPSHOT}'...")
                self.vag.snapshot_restore(CVEX_SNAPSHOT)
                print("Done")
                self.ssh = SSH(self.vag)
            else:
                self._start_vm()

    def destroy(self):
        print(f"Destroying VM '{self.vm_name}'...")
        try:
            self.vag.destroy()
            print("Done")
            try:
                shutil.rmtree(self.destination)
            except:
                pass
        except:
            print("Failed")

    def stop(self):
        print(f"Stopping VM '{self.vm_name}'...")
        try:
            self.vag.halt()
            print("Done")
        except:
            print("Failed")

def _read_output(runner: fabric.runners.Remote):
    try:
        stdouts = 0
        while True:
            if runner.program_finished.is_set():
                return
            new_stdouts = len(runner.stdout)
            if new_stdouts > stdouts:
                for i in range(stdouts, new_stdouts):
                    print(runner.stdout[i])
            stdouts = new_stdouts
            time.sleep(0.1)
    except:
        return

def _get_windows_private_network_interface_index(vm: VM):
    route_print = vm.ssh.run_command("route print")
    id = re.search(r"(\d+)\.\.\.([0-9a-fA-F]{2} ){6}\.\.\.\.\.\.Intel\(R\) PRO/1000 MT Desktop Adapter #2", route_print)
    if not id:
        print(f"'route print' returned unknown data:\n{route_print}")
        sys.exit(1)
    return id.group(1)

def run_exploit(vms: dict, attacker_vm: str, command: str, output_dir: str):
    mitmdump_runner = None
    tcpdump_runner = None
    mitmdump_thread = None
    tcpdump_thread = None

    if ROUTER_VM in vms:
        try:
            vms[ROUTER_VM].ssh.run_command("pkill mitmdump")
        except:
            pass
        try:
            vms[ROUTER_VM].ssh.run_command("sudo pkill tcpdump")
        except:
            pass
        try:
            vms[ROUTER_VM].ssh.run_command(f"rm -rf {CVEX_TEMP_FOLDER_LINUX}")
        except:
            pass
        vms[ROUTER_VM].ssh.run_command(f"mkdir {CVEX_TEMP_FOLDER_LINUX}")
        vms[ROUTER_VM].ssh.run_command("sudo sysctl net.ipv4.ip_forward=1")
        vms[ROUTER_VM].ssh.run_command("sudo iptables -t nat -I PREROUTING --src 0/0 --dst 0/0 -p tcp --dport 443 -j REDIRECT --to-ports 8080")
        tcpdump_runner = vms[ROUTER_VM].ssh.run_command(
            f"sudo tcpdump -i eth1 -U -w {TCPDUMP_LOG_PATH}", is_async=True)
        mitmdump_runner = vms[ROUTER_VM].ssh.run_command(
            f"mitmdump --mode transparent -k --set block_global=false -w {MITMDUMP_LOG_PATH}",
            is_async=True, until="Transparent Proxy listening at")
        mitmdump_thread = threading.Thread(target=_read_output, args=[mitmdump_runner])
        mitmdump_thread.start()
        tcpdump_thread = threading.Thread(target=_read_output, args=[tcpdump_runner])
        tcpdump_thread.start()

        for vm_name, vm in vms.items():
            if vm_name == ROUTER_VM:
                continue
            if vm.vm_type == "windows":
                vm.ssh.run_command("route DELETE 192.168.56.0")
                id = _get_windows_private_network_interface_index(vm)
                vm.ssh.run_command(f"route ADD 192.168.56.0 MASK 255.255.255.0 {vms[ROUTER_VM].ip} if {id}")
            elif vm.vm_type == "linux":
                # TODO
                pass

    for vm_name, vm in vms.items():
        command = command.replace(f"%{vm_name}%", vm.ip)
    vms[attacker_vm].ssh.run_command(command)

    if ROUTER_VM in vms:
        print("Wait for 10 seconds to let tcpdump flush log on disk...")
        time.sleep(5)
        vms[ROUTER_VM].ssh.send_ctrl_c(mitmdump_runner)
        vms[ROUTER_VM].ssh.send_ctrl_c(tcpdump_runner)

        vms[ROUTER_VM].ssh.download_file(f"{output_dir}/{TCPDUMP_LOG}", TCPDUMP_LOG_PATH)
        print(f"tcpdump log was stored to {output_dir}/{TCPDUMP_LOG}")
        vms[ROUTER_VM].ssh.download_file(f"{output_dir}/{MITMDUMP_LOG}", MITMDUMP_LOG_PATH)
        print(f"mitmdump log was stored to {output_dir}/{MITMDUMP_LOG}")


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
    args = parser.parse_args()

    output_dir = Path(args.output)
    if not output_dir.exists():
        output_dir.mkdir()
    elif not output_dir.is_dir():
        print(f"{output_dir} is not a directory")
        sys.exit(1)

    with args.config as f:
        infrastructure = yaml.safe_load(f)
    
    infrastructure = verify_infrastructure_config(infrastructure, args.config.name)
    if not infrastructure:
        print("Configuration mismatch")
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

    run_exploit(vms, infrastructure['exploit']['vm'], infrastructure['exploit']['command'], args.output)

    #for vm_name, vm in vms.items():
    #    vm.stop()

    sys.exit(0)

if __name__ == "__main__":
    main()
