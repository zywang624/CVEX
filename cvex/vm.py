import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile

import vagrant

from cvex.consts import *
from cvex.ip_manager import IPManager
from cvex.logger import get_logger
from cvex.ssh import SSH


class VM:
    ips: IPManager
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

    def __init__(self, vms: list, vm_name: str, config: dict, ips: IPManager, cve: str = "", destination: str = ""):
        self.ips = ips
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
                     f"  config.vm.hostname = \"{self.vm_name}\"\n"
                     f"\n"
                     ))
            f.write(data[pos + len(config):])

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
        self.ssh.upload_file("data/certindex", "certindex")
        self.ssh.upload_file("data/default.cfg", "/home/vagrant/.mitmproxy/default.cfg")
        self.ssh.run_command(f"openssl ca -config /home/{self.vag.user()}/.mitmproxy/default.cfg -gencrl -inform PEM -keyfile /home/{self.vag.user()}/.mitmproxy/mitmproxy-ca.pem -cert /home/{self.vag.user()}/.mitmproxy/mitmproxy-ca-cert.pem -out /home/{self.vag.user()}/.mitmproxy/root.crl.pem")
        self.ssh.run_command(f"openssl crl -inform PEM -in /home/{self.vag.user()}/.mitmproxy/root.crl.pem -outform DER -out /home/{self.vag.user()}/.mitmproxy/root.crl")

    def _init_windows(self):
        self.log.info("Initializing the Windows VM")
        self.ssh.run_command("curl https://download.sysinternals.com/files/ProcessMonitor.zip -o ProcessMonitor.zip")
        self.ssh.run_command("mkdir C:\\Tools")
        self.ssh.run_command("tar -xf ProcessMonitor.zip -C C:\\Tools")

        router = self._get_vm(ROUTER_VM)
        if router:
            # Install the Certificate Authority (root) certificate
            local_cert = tempfile.NamedTemporaryFile()
            router.ssh.download_file(local_cert.name, f"/home/{router.vag.user()}/.mitmproxy/mitmproxy-ca-cert.cer")
            dest_crt = f"C:\\Users\\{self.vag.user()}\\mitmproxy-ca-cert.cer"
            self.ssh.upload_file(local_cert.name, f"/{dest_crt}")
            self.ssh.run_command((f"powershell \""
                                  f"Import-Certificate -FilePath '{dest_crt}' -CertStoreLocation Cert:\LocalMachine\Root\""))
            # Install the empty Certificate Revocation List
            local_crl = tempfile.NamedTemporaryFile()
            router.ssh.download_file(local_crl.name, f"/home/{router.vag.user()}/.mitmproxy/root.crl")
            dest_crl = f"C:\\Users\\{self.vag.user()}\\root.crl"
            self.ssh.upload_file(local_crl.name, f"/{dest_crl}")
            self.ssh.run_command(f"certutil -addstore CA {dest_crl}")

    def _init_linux(self):
        self.log.info("Initializing the Linux VM")
        router = self._get_vm(ROUTER_VM)
        if router:
            # Install the Certificate Authority (root) certificate
            local_cert = tempfile.NamedTemporaryFile()
            router.ssh.download_file(local_cert.name, f"/home/{router.vag.user()}/.mitmproxy/mitmproxy-ca-cert.cer")
            remote_tmp_cert = "/tmp/mitmproxy-ca-cert.crt"
            self.ssh.upload_file(local_cert.name, remote_tmp_cert)
            self.ssh.run_command(f"sudo mv {remote_tmp_cert} /usr/local/share/ca-certificates")
            self.ssh.run_command("sudo update-ca-certificates")

    def _run_shell_command(self, command: list[str], cwd: str | None = None, show_progress: bool = False) -> bytes:
        output = b""
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd)
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
            "host": rb"HostName (\d+\.\d+\.\d+\.\d+)",
            "user": rb"User (\w+)",
            "password": rb"Password (\w+)",
            "port": rb"Port (\d+)"
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
        # ansible_playbook_runner.Runner([inventory], self.playbook).run()
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
        self.ip = self.ips.generate_new_ip(self.destination)
        self._configure_vagrantfile()
        self.ips.write_private_ip(self.destination, self.image, self.ip)

    def _start_vm(self):
        self.log.info("Starting the VM %s...", self.vm_name)
        try:
            self.vag.up()
        except:
            self.log.critical("VM %s timed out. Please wait until the VM is started and then re-start CVEX.",
                              self.vm_name)
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
            self.ip = self.ips.read_private_ip(self.destination)
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
                self.ip = self.ips.read_private_ip(self.destination)
                self.log.info("Restoring VM %s (%s) to snapshot '%s'...", self.vm_name, self.ip, self.cve)
                try:
                    self.vag.snapshot_restore(self.cve)
                except:
                    self.vag.reload()
                self.ssh = SSH(self.vag, self.vm_name)
            elif INIT_SNAPSHOT in snapshots:
                self.ip = self.ips.read_private_ip(self.destination)
                self.log.info("Restoring VM %s (%s) to snapshot '%s'...", self.vm_name, self.ip, INIT_SNAPSHOT)
                try:
                    self.vag.snapshot_restore(INIT_SNAPSHOT)
                except:
                    self.vag.reload()
                self.ssh = SSH(self.vag, self.vm_name)
                self._provision_vm()
                self.log.info("Creating snapshot '%s' for VM %s (%s)...", self.cve, self.vm_name, self.ip)
                self.vag.snapshot_save(self.cve)
            else:
                self.ip = self.ips.read_private_ip(self.destination)
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
