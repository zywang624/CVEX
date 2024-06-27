import vagrant
import argparse
import threading
import os
import time
import paramiko
import signal
import yaml
import sys
import ansible_playbook_runner

ROUTER_VM = "router"
CVEX_SNAPSHOT = "cvex"
CVEX_TEMP_FOLDER_LINUX = "/tmp/cvex"
CVEX_TEMP_FOLDER_WINDOWS = "cvex"

MITMDUMP_LOG = "mitmdump.stream"
MITMDUMP_LOG_PATH = f"/tmp/{MITMDUMP_LOG}"
TCPDUMP_LOG = "raw.pcap"
TCPDUMP_LOG_PATH = f"/tmp/{TCPDUMP_LOG}"

class SSH:
    ssh: paramiko.client.SSHClient

    def __init__(self, vm: vagrant.Vagrant):
        self.ssh = self._ssh_connect(vm)

    def _ssh_connect(self, vm: vagrant.Vagrant) -> paramiko.client.SSHClient:
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"Retrieving SSH configuration of VM...")
        hostname=vm.hostname()
        port=vm.port()
        username=vm.user()
        key_filename=vm.keyfile()
        print("Done")
        print(f"Connecting to {hostname}:{port} over SSH...")
        client.connect(hostname=hostname, port=port, username=username, key_filename=key_filename)
        print("Done")
        return client

    def _send_ctrl_c(self, stdin):
        message = paramiko.Message()
        message.add_byte(paramiko.common.cMSG_CHANNEL_REQUEST)
        message.add_int(stdin.channel.remote_chanid)
        message.add_string("signal")
        message.add_boolean(False)
        message.add_string(signal.Signals.SIGTERM.name[3:])
        stdin.channel.transport._send_user_message(message)

    def run_command(self, command: str):
        print(f"Executing '{command}'...")
        stdin, stdout, _ = self.ssh.exec_command(command, get_pty=True)
        for line in stdout:
            print(line)
            if "mitmdump" in command and "server disconnect" in line:
                self._send_ctrl_c(stdin)
                break
        stdout.channel.close()
        stdin.channel.close()

    def upload_file(self, src: str, dst: str):
        print(f"Uploading '{dst}'...")
        with self.ssh.open_sftp() as sftp:
            sftp.put(src, dst)
        print("Done")

    def download_file(self, src: str, dst: str):
        print(f"Downloading '{dst}'...")
        with self.ssh.open_sftp() as sftp:
            sftp.get(src, dst)
        print("Done")


private_ip = 1

class VM:
    vag: vagrant.Vagrant
    vm_name: str
    image: str
    destination: str
    type: str
    playbook: str
    files: dict
    ip: str
    ssh: SSH

    def __init__(self, vm_name: str, config: dict):
        self.vag = vagrant.Vagrant(config['destination'])
        self.vm_name = vm_name
        self.image = config['image']
        self.destination = config['destination']
        self.type = config['type']
        if 'playbook' in config:
            self.playbook = config['playbook']
        else:
            self.playbook = None
        global private_ip
        self.ip = f"192.168.56.{private_ip}"
        private_ip += 1
        self.ssh = SSH(self.vag)
    
    def _configure_vagrantfile(self):
        vagrantfile = os.path.join(self.destination, "Vagrantfile")
        if os.path.exists(vagrantfile):
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
        
    def _init_vm(self):
        print(f"Initializing VM '{self.vm_name}'...")
        self.vag.init(self.vm_name, self.image)
        print("Done")
        self._configure_vagrantfile()
        print(f"Starting VM '{self.vm_name}'...")
        self.vag.up(vm_name=self.vm_name)
        print("Done")
        self._run_ansible()

    def _init_router():
        pass

    def _run_ansible(self):
        if not self.playbook:
            return
        inventory = os.path.join(self.destination, "inventory.ini")
        with open(inventory, "w") as f:
            if self.type == "windows":
                print(f"Retrieving WinRM configuration of '{self.vm_name}'...")
                # TODO: Vagrant API doesn't show WinRM config (???)
                data = (f"{self.vm_name} "
                        f"ansible_connection=winrm "
                        f"ansible_winrm_scheme=http "
                        f"ansible_host={self.vag.hostname()} "
                        f"ansible_port={self.vag.port()} "
                        f"ansible_user={self.vag.user()} "
                        f"ansible_password={self.vag.password()}")
            elif self.type == "linux":
                print(f"Retrieving SSH configuration of '{self.vm_name}'...")
                data = (f"{self.vm_name} "
                        f"ansible_host={self.vag.hostname()} "
                        f"ansible_port={self.vag.port()} "
                        f"ansible_user={self.vag.user()} "
                        f"ansible_ssh_private_key_file={self.vag.keyfile()} "
                        f"ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new'")
            f.write(data)
        print(f"Inventory '{inventory}' has been created for VM '{self.vm_name}'")
        print(f"Executing Ansible playbook '{self.playbook}' for '{self.vm_name}'...")
        #ansible_playbook_runner.Runner([inventory], self.playbook).run()
        print("Done")

    def run_vm(self):
        print(f"Retrieving status of '{self.vm_name}'...")
        status = self.vag.status()
        if status[0].state == "not_created":
            self._init_vm()
            if self.vm_name == ROUTER_VM:
                self._init_router()
            print(f"Creating snapshot '{CVEX_SNAPSHOT}' for VM '{self.vm_name}'...")
            self.vag.snapshot_save(CVEX_SNAPSHOT)
            print("Done")
        elif status[0].state != "running":
            snapshots = self.vag.snapshot_list()
            if CVEX_SNAPSHOT not in snapshots:
                print("Configuration mismatch, please try from scratch")
                sys.exit(1)
            print(f"Restoring VM '{self.vm_name}' to snapshot '{CVEX_SNAPSHOT}'...")
            self.vag.snapshot_restore(CVEX_SNAPSHOT)
            print("Done")
        else:
            print(f"VM '{self.vm_name}' is already running, skipping initialization")

def mitmdump(ssh: paramiko.client.SSHClient):
    ssh.run_command(f"mitmdump --mode transparent -k --set block_global=false -w {MITMDUMP_LOG_PATH}")

def tcpdump(ssh: paramiko.client.SSHClient):
    ssh.run_command(f"sudo tcpdump -i eth1 -w {TCPDUMP_LOG_PATH}")

def run_exploit(vms: dict, attacker_vm: str, command: str, output_dir: str):
    # TODO: not finished
    mitmdump_thread = None
    tcpdump_thread = None
    if ROUTER_VM in vms:
        vms[ROUTER_VM].ssh.run_command(f"mkdir {CVEX_TEMP_FOLDER_LINUX}")
        vms[ROUTER_VM].ssh.run_command("sudo sysctl net.ipv4.ip_forward=1")
        vms[ROUTER_VM].ssh.run_command("sudo iptables -t nat -I PREROUTING --src 0/0 --dst 0/0 -p tcp --dport 443 -j REDIRECT --to-ports 8080")
        mitmdump_thread = threading.Thread(target=mitmdump, args=[vms[ROUTER_VM].ssh])
        mitmdump_thread.start()
        tcpdump_thread = threading.Thread(target=tcpdump, args=[vms[ROUTER_VM].ssh])
        tcpdump_thread.start()
    vms[attacker_vm].ssh.run_command(command)
    
    vms[ROUTER_VM].ssh.download_file(TCPDUMP_LOG_PATH, f"{output_dir}/{TCPDUMP_LOG}")
    vms[ROUTER_VM].ssh.download_file(MITMDUMP_LOG_PATH, f"{output_dir}/{MITMDUMP_LOG}")

def verify_infrastructure_config(config: dict) -> bool:
    if 'vms' not in config or not config['vms']:
        return False
    if len(config['vms']) >= 3 and ROUTER_VM not in config['vms']:
        return False
    for vm_name, data in config['vms'].items():
        if 'image' not in data or 'destination' not in data:
            return False
        if 'type' not in data or data['type'] not in ["linux", "windows"]:
            return False
        if 'ansible' in data and not os.path.exists(data['ansible']):
            return False
    if 'exploit' not in config or 'vm' not in config['exploit'] or 'command' not in config['exploit']:
        return False
    if config['exploit']['vm'] not in config['vms']:
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        prog="cvex",
        description="",
    )
    parser.add_argument("-c", "--config", help="Configuration of the infrastructure")
    parser.add_argument("-o", "--output", help="Directory for generated logs")
    args = parser.parse_args()

    if args.config is None:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.config):
        print(f"{args.config} does not exist")
        sys.exit(1)

    if not os.path.exists(args.output) or not os.path.isdir(args.output):
        print(f"{args.output} does not exist or not a directory")
        sys.exit(1)

    with open(args.config, "r") as f:
        infrastructure = yaml.safe_load(f)
    
    if not verify_infrastructure_config(infrastructure):
        print("Configuration mismatch")
        sys.exit(1)

    vms = {}
    for vm_name, config in infrastructure['vms'].items():
        if vm_name != "linux":
            continue
        vm = VM(vm_name, config)
        vm.run_vm()
        vm._run_ansible()
        vms[vm_name] = vm


main()
