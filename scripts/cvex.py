import argparse
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import fabric
import paramiko
import procmon_parser
import vagrant
import yaml

INFRASTRUCTURE_FILE = "infrastructure.yml"

CVEX_ROOT = "~/.cvex"

ROUTER_VM = "router"
ROUTER_DESTINATION = f"{CVEX_ROOT}/{ROUTER_VM}"
ROUTER_CONFIG = {
    "image" : "bento/ubuntu-22.04",
    "version" : "202404.23.0",
    "type" : "linux"
}

INIT_SNAPSHOT = "clean"

CVEX_TEMP_FOLDER_LINUX = "/tmp/cvex"
MITMDUMP_LOG = "router_mitmdump.stream"
MITMDUMP_LOG_PATH = f"{CVEX_TEMP_FOLDER_LINUX}/{MITMDUMP_LOG}"
TCPDUMP_LOG = "router_raw.pcap"
TCPDUMP_LOG_PATH = f"{CVEX_TEMP_FOLDER_LINUX}/{TCPDUMP_LOG}"

CVEX_TEMP_FOLDER_WINDOWS = "C:\\cvex"
PROCMON_PML_LOG = "procmon.pml"
PROCMON_PML_LOG_PATH = f"{CVEX_TEMP_FOLDER_WINDOWS}\\{PROCMON_PML_LOG}"
PROCMON_XML_LOG = "procmon.xml"
PROCMON_XML_LOG_PATH = f"{CVEX_TEMP_FOLDER_WINDOWS}\\{PROCMON_XML_LOG}"


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
    vms: list
    log: logging.Logger
    cve: str
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

    def _get_vm_destination(self, image: str, version: str):
        path = os.path.join(os.path.expanduser(CVEX_ROOT), image.replace("/", "_"), version)
        if not os.path.exists(path):
            return os.path.join(path, "1")
        instances = [f.name for f in os.scandir(path) if f.is_dir()]
        if not instances:
            return os.path.join(path, "1")
        free_instances = instances
        max_instance = 1
        for instance in instances:
            instance_path = os.path.join(path, instance)
            if int(instance) > max_instance:
                max_instance = int(instance)
            for vm in self.vms:
                if vm.destination == instance_path:
                    free_instances.remove(instance)
        if free_instances:
            return os.path.join(path, free_instances[0])
        else:
            return os.path.join(path, str(max_instance + 1))

    def __init__(self, vms: list, vm_name: str, config: dict, cve: str = "", destination: str = ""):
        self.vms = vms
        self.log = get_logger(vm_name)
        self.cve = cve
        self.image = config['image']
        self.version = config['version']
        if destination:
            self.destination = destination
        else:
            self.destination = self._get_vm_destination(self.image, self.version)
        self.vag = vagrant.Vagrant(self.destination)
        self.vm_name = vm_name
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
                     f"  config.vm.box_version = \"{self.version}\"\n"
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

    def _get_vm(self, vm_name: str) -> object | None:
        for vm in self.vms:
            if vm.vm_name == vm_name:
                return vm
        return None

    def _init_router(self):
        self.log.info("Initializing the router VM")
        self.ssh.run_command("wget https://downloads.mitmproxy.org/10.3.1/mitmproxy-10.3.1-linux-x86_64.tar.gz")
        self.ssh.run_command("sudo tar -xf mitmproxy-10.3.1-linux-x86_64.tar.gz -C /usr/bin")
        self.ssh.run_command("mitmdump --mode transparent", is_async=True, until="Transparent Proxy listening at")
        self.ssh.run_command("pkill mitmdump")

    def _init_windows(self):
        self.log.info("Initializing the Windows VM")
        self.ssh.run_command("curl https://download.sysinternals.com/files/ProcessMonitor.zip -o ProcessMonitor.zip")
        self.ssh.run_command("mkdir C:\\Tools")
        self.ssh.run_command("tar -xf ProcessMonitor.zip -C C:\\Tools")

        router = self._get_vm(ROUTER_VM)
        if router:
            local_cert = tempfile.NamedTemporaryFile()
            router.ssh.download_file(local_cert.name, f"/home/{router.vag.user()}/.mitmproxy/mitmproxy-ca-cert.cer")
            dest_crt = f"C:\\Users\\{self.vag.user()}\\mitmproxy-ca-cert.cer"
            self.ssh.upload_file(local_cert.name, f"/{dest_crt}")
            self.ssh.run_command((f"powershell \""
                                f"Import-Certificate -FilePath '{dest_crt}' -CertStoreLocation Cert:\LocalMachine\Root\""))

    def _init_linux(self):
        self.log.info("Initializing the Linux VM")
        router = self._get_vm(ROUTER_VM)
        if router:
            local_cert = tempfile.NamedTemporaryFile()
            router.ssh.download_file(local_cert.name, f"/home/{router.vag.user()}/.mitmproxy/mitmproxy-ca-cert.crt")
            remote_tmp_cert = "/tmp/mitmproxy-ca-cert.crt"
            self.ssh.upload_file(local_cert.name, remote_tmp_cert)
            self.ssh.run_command(f"sudo cp {remote_tmp_cert} /usr/local/share/ca-certificates")
            self.ssh.run_command(f"sudo mv {remote_tmp_cert} /etc/ssl/certs")
            self.ssh.run_command("sudo update-ca-certificates")

    def _run_shell_command(self, command: list[str], cwd: str | None = None, show_progress: bool = False) -> bytes:
        output = b""
        p = subprocess.Popen(command,stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd)
        for line in iter(p.stdout.readline, b''):
            if show_progress:
                self.log.info(line.decode().rstrip())
            else:
                self.log.debug(line.decode().rstrip())
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
                        f"ansible_password={config['password']} "
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
                        f"ansible_ssh_common_args='-o StrictHostKeyChecking=no'")
            f.write(data)
        self.log.info("Inventory %s has been created for VM %s", inventory, self.vm_name)
        self.log.info("Executing Ansible playbook %s for %s...", self.playbook, self.vm_name)
        #ansible_playbook_runner.Runner([inventory], self.playbook).run()
        result = self._run_shell_command(["ansible-playbook", "-i", inventory, self.playbook], show_progress=True)
        if b"unreachable=0" not in result or b"failed=0" not in result:
            sys.exit(1)

    def _provision_vm(self):
        self._run_ansible()
        if self.vm_name == ROUTER_VM:
            self._init_router()
        elif self.vm_type == "windows":
            self._init_windows()
        elif self.vm_type == "linux":
            self._init_linux()

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

        self.log.info("Creating snapshot '%s' for VM %s (%s)...", INIT_SNAPSHOT, self.vm_name, self.ip)
        self.vag.snapshot_save(INIT_SNAPSHOT)

        self.ssh = SSH(self.vag, self.vm_name)
        self._provision_vm()

        self.log.info("Creating snapshot '%s' for VM %s (%s)...", self.cve, self.vm_name, self.ip)
        self.vag.snapshot_save(self.cve)

    def _update_windows_hosts(self, vms: list):
        remote_hosts = "/C:\\Windows\\System32\\drivers\\etc\\hosts"
        local_hosts = tempfile.NamedTemporaryFile()
        self.ssh.download_file(local_hosts.name, remote_hosts)
        with open(local_hosts.name, "r") as f:
            hosts = f.read()
        ips = "\r\n"
        for vm in vms:
            if vm != self:
                ips += f"{vm.ip} {vm.vm_name}\r\n"
        self.log.debug("Setting ip hosts: %s", ips)
        hosts += ips
        with open(local_hosts.name, "w") as f:
            f.write(hosts)
        self.ssh.upload_file(local_hosts.name, remote_hosts)

    def _update_linux_hosts(self, vms: list):
        remote_hosts = "/etc/hosts"
        local_hosts = tempfile.NamedTemporaryFile()
        self.ssh.download_file(local_hosts.name, remote_hosts)
        with open(local_hosts.name, "r") as f:
            hosts = f.read()
        ips = "\n"
        for vm in vms:
            if vm != self:
                ips += f"{vm.ip} {vm.vm_name}\r\n"
        self.log.debug("Setting ip hosts: %s", ips)
        hosts += ips
        with open(local_hosts.name, "w") as f:
            f.write(hosts)
        self.ssh.upload_file(local_hosts.name, "/tmp/hosts")
        self.ssh.run_command(f"sudo mv /tmp/hosts {remote_hosts}")

    def update_hosts(self, vms: list):
        if self.vm_type == "windows":
            self._update_windows_hosts(vms)
        elif self.vm_type == "linux":
            self._update_linux_hosts(vms)

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
                self.log.info("Creating snapshot '%s' for VM %s (%s)...", INIT_SNAPSHOT, self.vm_name, self.ip)
                self.vag.snapshot_save(INIT_SNAPSHOT)

            if self.cve not in snapshots:
                self._provision_vm()
                self.log.info("Creating snapshot '%s' for VM %s (%s)...", self.cve, self.vm_name, self.ip)
                self.vag.snapshot_save(self.cve)
        else:
            self.log.info("Retrieving snapshot list of %s...", self.vm_name)
            snapshots = self.vag.snapshot_list()

            if self.cve in snapshots:
                self.ip = self._read_ip()
                self.log.info("Restoring VM %s (%s) to snapshot '%s'...", self.vm_name, self.ip, self.cve)
                self.vag.snapshot_restore(self.cve)
                self.ssh = SSH(self.vag, self.vm_name)
            elif INIT_SNAPSHOT in snapshots:
                self.ip = self._read_ip()
                self.log.info("Restoring VM %s (%s) to snapshot '%s'...", self.vm_name, self.ip, INIT_SNAPSHOT)
                self.vag.snapshot_restore(INIT_SNAPSHOT)
                self.ssh = SSH(self.vag, self.vm_name)

                self._provision_vm()
                self.log.info("Creating snapshot '%s' for VM %s (%s)...", self.cve, self.vm_name, self.ip)
                self.vag.snapshot_save(self.cve)
            else:
                self.ip = self._read_ip()
                self._start_vm()

    def destroy(self):
        self.log.info("Destroying VM %s...", self.image)
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
    vms: list

    def __init__(self, vms: list[VM]):
        self.log = get_logger("exploit")
        self.vms = vms

    def _read_output(self, runner: fabric.runners.Remote):
        try:
            stdouts = 0
            while True:
                if runner.program_finished.is_set():
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

    def _get_vm(self, vm_name: str) -> VM | None:
        for vm in self.vms:
            if vm.vm_name == vm_name:
                return vm
        return None

    def _start_router_sniffing(self):
        router = self._get_vm(ROUTER_VM)
        if not router:
            return
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

        for vm in self.vms:
            if vm.vm_name == ROUTER_VM:
                continue
            if vm.vm_type == "windows":
                try:
                    vm.ssh.run_command((f"powershell \""
                                        f"Get-NetAdapter -Name 'Ethernet 2' | "
                                        f"New-NetIPAddress -IPAddress {vm.ip} -DefaultGateway {router.ip} -PrefixLength 24\""))
                except:
                    pass
                vm.ssh.run_command("route DELETE 192.168.56.0")
                id = self._get_windows_private_network_interface_index(vm)
                vm.ssh.run_command(f"route ADD 192.168.56.0 MASK 255.255.255.0 {router.ip} if {id}")
            elif vm.vm_type == "linux":
                try:
                    vm.ssh.run_command(f"sudo ip route change 192.168.56.0/24 via {router.ip} dev eth1")
                except:
                    pass
                vm.ssh.run_command("sudo systemctl restart ufw")

    def _stop_router_sniffing(self, output_dir: str):
        router = self._get_vm(ROUTER_VM)
        if not router:
            return

        self.log.info("Wait for 5 seconds to let tcpdump flush log on disk...")
        time.sleep(5)
        router.ssh.send_ctrl_c(router.mitmdump_runner)
        router.ssh.send_ctrl_c(router.tcpdump_runner)
        #router.mitmdump_thread.join()
        #router.tcpdump_thread.join()

        local = f"{output_dir}/{TCPDUMP_LOG}"
        router.ssh.download_file(local, TCPDUMP_LOG_PATH)
        local = f"{output_dir}/{MITMDUMP_LOG}"
        router.ssh.download_file(local, MITMDUMP_LOG_PATH)

    def _start_windows_api_tracing(self, vm: VM):
        with open("data/procmon.pmc", "rb") as f:
            config = procmon_parser.load_configuration(f)
        config["FilterRules"] = [
        procmon_parser.Rule(
            procmon_parser.Column.PROCESS_NAME,
            procmon_parser.RuleRelation.CONTAINS,
            vm.trace,
            procmon_parser.RuleAction.INCLUDE)]
        local_config = tempfile.NamedTemporaryFile()
        with open(local_config.name, "wb") as f:
            procmon_parser.dump_configuration(config, f)
        try:
            vm.ssh.run_command("taskkill /IM Procmon.exe /F")
        except:
            pass
        try:
            vm.ssh.run_command(f"rmdir /S /Q {CVEX_TEMP_FOLDER_WINDOWS}")
        except:
            pass
        vm.ssh.run_command(f"mkdir {CVEX_TEMP_FOLDER_WINDOWS}")

        remote_config_path = f"{CVEX_TEMP_FOLDER_WINDOWS}\\config.pmc"
        vm.ssh.upload_file(local_config.name, f"/{remote_config_path}")
        vm.ssh.run_command(
            f"C:\\Tools\\Procmon.exe /AcceptEula /BackingFile {PROCMON_PML_LOG_PATH} /LoadConfig {remote_config_path} /Quiet",
            is_async=True)

    def _stop_windows_api_tracing(self, vm: VM, output_dir: str):
        vm.ssh.run_command("C:\\Tools\\Procmon.exe /AcceptEula /Terminate")
        vm.ssh.run_command(f"C:\Tools\Procmon.exe /AcceptEula /OpenLog {PROCMON_PML_LOG_PATH} /SaveAs {PROCMON_XML_LOG_PATH}")
        vm.ssh.download_file(f"{output_dir}/{vm.vm_name}_{PROCMON_PML_LOG}", f"/{PROCMON_PML_LOG_PATH}")
        vm.ssh.download_file(f"{output_dir}/{vm.vm_name}_{PROCMON_XML_LOG}", f"/{PROCMON_XML_LOG_PATH}")

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
                runner = vm.ssh.run_command(f"sudo strace -p {pid} -o {log} -v", is_async=True, until="attached")
                vm.strace[log] = runner

    def _stop_linux_api_tracing(self, vm: VM, output_dir: str):
        for _, runner in vm.strace.items():
            vm.ssh.send_ctrl_c(runner)
        for log, _ in vm.strace.items():
            out = f"{output_dir}/{log[len(CVEX_TEMP_FOLDER_LINUX)+1:]}"
            vm.ssh.download_file(out, log)
            self.log.info("strace log was stored to %s", out)

    def _start_api_tracing(self):
        for vm in self.vms:
            if vm.trace:
                if vm.vm_type == "windows":
                    self._start_windows_api_tracing(vm)
                elif vm.vm_type == "linux":
                    self._start_linux_api_tracing(vm)

    def _stop_api_tracing(self, output_dir: str):
        for vm in self.vms:
            if vm.trace:
                if vm.vm_type == "windows":
                    self._stop_windows_api_tracing(vm, output_dir)
                elif vm.vm_type == "linux":
                    self._stop_linux_api_tracing(vm, output_dir)

    def _get_command(self, command_template: str):
        command = command_template
        for vm in self.vms:
            command = command.replace(f"%{vm.vm_name}%", vm.ip)
        return command

    def run(self, attacker_vm: str, command: str, output_dir: str):
        vm = self._get_vm(attacker_vm)
        if not vm:
            self.log.critical("Can't find VM %s", attacker_vm)
            sys.exit(1)

        self._start_router_sniffing()
        self._start_api_tracing()

        vm.ssh.run_command(self._get_command(command))

        self._stop_router_sniffing(output_dir)
        self._stop_api_tracing(output_dir)


def verify_infrastructure_config(config: dict, config_dir: str) -> dict | None:
    if 'cve' not in config:
        return None
    if 'vms' not in config or not config['vms']:
        return None
    if ROUTER_VM in config['vms']:
        return None
    for vm_name, data in config['vms'].items():
        if 'image' not in data or 'version' not in data:
            return None
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
    parser.add_argument("-c", "--config",  help="Directory with the configuration of the infrastructure")
    parser.add_argument("-o", "--output",  help="Directory for generated logs", default="logs")
    parser.add_argument("-l", "--list",    help="List all cached VMs", default=False, action="store_true")
    parser.add_argument("-d", "--destroy", help="Destroy cached VMs (destroy all if empty)")
    parser.add_argument("-v", "--verbose", help="Verbose logs", default=False, action="store_true")
    args = parser.parse_args()

    if args.verbose:
        global log_level
        log_level = logging.DEBUG
    log = get_logger("main")

    if args.list or args.destroy != None:
        images = [f.name for f in os.scandir(os.path.expanduser(CVEX_ROOT)) if f.is_dir()]
        if not images:
            log.info("There are no cached VMs")
            sys.exit(0)
        if args.list:
            log.info("Cached VMs:")
        if ROUTER_VM in images:
            if args.list:
                log.info("%s", ROUTER_VM)
            if args.destroy == "" or args.destroy == ROUTER_VM:
                vm = VM([],
                        ROUTER_VM,
                        ROUTER_CONFIG,
                        cve=ROUTER_VM,
                        destination=os.path.expanduser(ROUTER_DESTINATION))
                vm.destroy()
        for image in images:
            if image != ROUTER_VM:
                versions = [f.name for f in os.scandir(os.path.join(os.path.expanduser(CVEX_ROOT), image)) if f.is_dir()]
                for version in versions:
                    if args.list:
                        log.info("%s/%s", image, version)
                    if args.destroy == "" or args.destroy == f"{image}/{version}":
                        config = {
                            "image" : image.replace("_", "/"),
                            "version" : version,
                            "type" : "unknown"
                        }
                        vm = VM("unknown", config)
                        vm.destroy()
        try:
            shutil.rmtree(CVEX_ROOT)
        except:
            pass
        sys.exit(0)

    output_dir = Path(args.output)
    if not output_dir.exists():
        output_dir.mkdir()
    elif not output_dir.is_dir():
        log.critical("%s is not a directory", output_dir)
        sys.exit(1)

    infrastructure_file = os.path.join(args.config, INFRASTRUCTURE_FILE)
    if not args.config or not os.path.exists(infrastructure_file):
        parser.print_help()
        sys.exit(1)

    with open(infrastructure_file, "r") as f:
        infrastructure = yaml.safe_load(f)

    infrastructure = verify_infrastructure_config(infrastructure, args.config)
    if not infrastructure:
        log.critical("Configuration mismatch")
        sys.exit(1)

    vms = []

    if len(infrastructure['vms']) > 1:
        vm = VM([],
                ROUTER_VM,
                ROUTER_CONFIG,
                cve=ROUTER_VM,
                destination=os.path.abspath(os.path.expanduser(ROUTER_DESTINATION)))
        vm.run_vm()
        vms.append(vm)
    for vm_name, config in infrastructure['vms'].items():
        vm = VM(vms, vm_name, config, cve=infrastructure['cve'])
        vm.run_vm()
        vms.append(vm)

    for vm in vms:
        if vm.vm_name != ROUTER_VM:
            vm.update_hosts(vms)

    exploit = Exploit(vms)
    exploit.run(infrastructure['exploit']['vm'], infrastructure['exploit']['command'], args.output)

    #for vm in vms:
    #    vm.stop()

    sys.exit(0)

if __name__ == "__main__":
    main()
