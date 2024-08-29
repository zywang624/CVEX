import logging
import os
import shutil
import subprocess
import sys
import vagrant

from cvex.consts import *
from cvex.logger import get_logger
from cvex.ssh import SSH


class VMTemplate:
    VM_TYPE_LINUX = "linux"
    VM_TYPE_WINDOWS = "windows"

    log: logging.Logger
    vm_name: str
    image: str
    version: str
    vm_type: str
    trace: str | None
    playbooks: list[Path]
    command: str | None

    def __init__(self,
                 vm_name: str,
                 image: str,
                 version: str,
                 vm_type: str,
                 trace: str | None = None,
                 playbooks: list[Path] = [],
                 command: str | None = None):
        self.log = get_logger(vm_name)
        self.vm_name = vm_name
        self.image = image
        self.version = version
        if vm_type != self.VM_TYPE_LINUX and vm_type != self.VM_TYPE_WINDOWS:
            self.log.critical("Unknown VM type: %r", vm_type)
            sys.exit(1)
        self.vm_type = vm_type
        self.trace = trace
        for playbook in playbooks:
            if not playbook.exists():
                self.log.critical("%r does not exist", playbook)
                sys.exit(1)
        self.playbooks = playbooks
        self.command = command


current_ip = 2

class VM:
    log: logging.Logger
    vm_name: str
    image: str
    version: str
    vm_type: str
    trace: str | None
    playbooks: list[Path]
    command: str | None
    cve: str
    destination: Path
    vag: vagrant.Vagrant
    files: dict
    ip: str
    ssh: SSH

    def _get_vm_destination(self, vms: list, image: str, version: str) -> Path:
        path = Path(CVEX_ROOT, image.replace("/", "_"), version)
        if not path.exists():
            return Path(path, "1")
        instances = [f.name for f in os.scandir(path) if f.is_dir()]
        if not instances:
            return Path(path, "1")
        free_instances = instances
        max_instance = 1
        for instance in instances:
            instance_path = Path(path, instance)
            if int(instance) > max_instance:
                max_instance = int(instance)
            for vm in vms:
                if vm.destination == instance_path:
                    free_instances.remove(instance)
        if free_instances:
            return Path(path, free_instances[0])
        else:
            return Path(path, str(max_instance + 1))

    def __init__(self,
                 vms: list,
                 template: VMTemplate,
                 cve: str,
                 destination: Path | None = None):
        self.log = get_logger(template.vm_name)
        self.vm_name = template.vm_name
        self.image = template.image
        self.version = template.version
        self.vm_type = template.vm_type
        self.trace = template.trace
        self.playbooks = template.playbooks
        self.command = template.command
        self.cve = cve
        if destination:
            self.destination = destination
        else:
            self.destination = self._get_vm_destination(vms, self.image, self.version)
        self.vag = vagrant.Vagrant(self.destination)
        global current_ip
        self.ip = f"192.168.56.{current_ip}"
        current_ip += 1

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
                     f"  config.vm.network \"private_network\", ip: \"{self.ip}\"\n"
                     f"\n"
                     ))
            f.write(data[pos + len(config):])

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

    def _provision_vm(self, router = None):
        self.init(router)
        if self.playbooks:
            inventory = self.get_ansible_inventory()
            self.log.info("Inventory %s has been created for VM %s", inventory, self.vm_name)
            for playbook in self.playbooks:
                self.log.info("Executing Ansible playbook %s for %s...", playbook, self.vm_name)
                # ansible_playbook_runner.Runner([inventory], self.playbook).run()
                result = self._run_shell_command(["ansible-playbook", "-i", inventory, playbook], show_progress=True)
                if b"unreachable=0" not in result or b"failed=0" not in result:
                    sys.exit(1)

    def _init_vm(self):
        self.log.info("Initializing a new VM %s at %s...", self.vm_name, self.destination)
        self.vag.init(box_url=self.image)
        self._configure_vagrantfile()

    def _start_vm(self, router = None):
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
        self._provision_vm(router)

        self.log.info("Creating snapshot '%s' for VM %s (%s)...", self.cve, self.vm_name, self.ip)
        self.vag.snapshot_save(self.cve)

    def run(self, router = None):
        if not os.path.exists(self.destination):
            os.makedirs(self.destination)
            self._init_vm()
            self._start_vm(router)
            return

        self.log.info("Retrieving status of %s...", self.vm_name)
        status = self.vag.status()

        if status[0].state == "not_created":
            self._init_vm()
            self._start_vm(router)
        elif status[0].state == "running":
            self.log.info("VM %s (%s) is already running", self.vm_name, self.ip)
            self.ssh = SSH(self.vag, self.vm_name)

            self.log.info("Retrieving snapshot list of %s...", self.vm_name)
            snapshots = self.vag.snapshot_list()

            if INIT_SNAPSHOT not in snapshots:
                self.log.info("Creating snapshot '%s' for VM %s (%s)...", INIT_SNAPSHOT, self.vm_name, self.ip)
                self.vag.snapshot_save(INIT_SNAPSHOT)

            if self.cve not in snapshots:
                self._provision_vm(router)
                self.log.info("Creating snapshot '%s' for VM %s (%s)...", self.cve, self.vm_name, self.ip)
                self.vag.snapshot_save(self.cve)
        else:
            self.log.info("Retrieving snapshot list of %s...", self.vm_name)
            snapshots = self.vag.snapshot_list()

            if self.cve in snapshots:
                self.log.info("Restoring VM %s (%s) to snapshot '%s'...", self.vm_name, self.ip, self.cve)
                try:
                    self.vag.snapshot_restore(self.cve)
                except:
                    self.vag.reload()
                self.ssh = SSH(self.vag, self.vm_name)
            elif INIT_SNAPSHOT in snapshots:
                self.log.info("Restoring VM %s (%s) to snapshot '%s'...", self.vm_name, self.ip, INIT_SNAPSHOT)
                try:
                    self.vag.snapshot_restore(INIT_SNAPSHOT)
                except:
                    self.vag.reload()
                self.ssh = SSH(self.vag, self.vm_name)
                self._provision_vm(router)

                self.log.info("Creating snapshot '%s' for VM %s (%s)...", self.cve, self.vm_name, self.ip)
                self.vag.snapshot_save(self.cve)
            else:
                self._start_vm(router)

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
