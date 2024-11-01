import argparse
import logging
import os
import shutil
import sys
import re

import yaml

from cvex.consts import *
from cvex.logger import get_logger, set_log_level
from cvex.vm import VM, VMTemplate
from cvex.windowsvm import WindowsVM
from cvex.linuxvm import LinuxVM
from cvex.routervm import RouterVM


class CVEX:
    vm_templates: list[VMTemplate]
    ports: list[int]

    def __init__(self, cve_dir: Path):
        self.log = get_logger("CVEX")

        cvex_yml = Path(cve_dir, CVEX_FILE)
        if not cvex_yml.exists():
            self.log.critical("%s does not exist", cvex_yml)
            sys.exit(1)

        for root, dirs, files in os.walk(Path(cve_dir, "data")):
            for fil in files:
                with open(Path(root, fil), "rb") as f:
                    if b"git-lfs.github.com" in f.readline(256):
                        self.log.critical("Git LFS files detected. Please install Git LFS and pull the files: sudo apt install git-lfs; git lfs pull")
                        sys.exit(1)

        try:
            with open(cvex_yml, "r") as f:
                cvex = yaml.safe_load(f)
        except:
            self.log.critical("%s is not a YAML file", cvex_yml)
            sys.exit(1)

        if 'blueprint' not in cvex:
            self.log.critical("%s: configuration mismatch", cvex_yml)
            sys.exit(1)

        blueprint_yml = Path(Path(__file__).parent.parent.parent, "blueprints", cvex['blueprint'], "blueprint.yml")
        if not blueprint_yml.exists():
            self.log.critical("Blueprint %r does not exist", blueprint_yml)
            sys.exit(1)
        try:
            with open(blueprint_yml, "r") as f:
                vm_templates = yaml.safe_load(f)
        except:
            self.log.critical("%s is not a YAML file", blueprint_yml.name)
            sys.exit(1)
        self.vm_templates = []
        for vm_name, data in vm_templates.items():
            if 'image' not in data or 'version' not in data or 'type' not in data:
                self.log.critical("%s: configuration mismatch", blueprint_yml)
                sys.exit(1)
            playbooks = []
            if 'playbook' in data:
                playbooks.append(Path(Path(__file__).parent.parent.parent, "blueprints", cvex['blueprint'], data['playbook']))
            trace = None
            command = None
            if vm_name in cvex:
                if 'trace' in cvex[vm_name]:
                    trace = cvex[vm_name]['trace']
                if 'playbook' in cvex[vm_name]:
                    playbooks.append(Path(cve_dir, cvex[vm_name]['playbook']))
                if 'command' in cvex[vm_name]:
                    command = cvex[vm_name]['command']
                    if type(command) == str:
                        command = [command]
            self.vm_templates.append(VMTemplate(vm_name,
                                            data['image'],
                                            data['version'],
                                            data['type'],
                                            trace,
                                            playbooks,
                                            command))
        if not self.vm_templates:
            self.log.critical("%s: configuration mismatch", blueprint_yml)
            sys.exit(1)

        if 'ports' in cvex:
            if type(cvex['ports']) == int:
                self.ports = [cvex['ports']]
            elif type(cvex['ports']) == list:
                self.ports = []
                for port in cvex['ports']:
                    if type(port) != int:
                        self.log.critical("%s: bad ports", cvex_yml)
                        sys.exit(1)
                    self.ports.append(port)
            else:
                self.log.critical("%s: bad ports", cvex_yml)
                sys.exit(1)
        else:
            self.ports = [DEFAULT_PORT]
        for port in self.ports:
            if port < 1 or port > 0xFFFF:
                self.log.critical("%s: bad ports", cvex_yml)
                sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="cvex",
        description="",
    )
    parser.add_argument("cve", help="CVE directory name", nargs='?')
    parser.add_argument("-o", "--output", help="Directory for generated logs (\"out\" by default)", default="out")
    parser.add_argument("-l", "--list", help="List all cached VMs", default=False, action="store_true")
    parser.add_argument("-d", "--destroy", help="Name of the cached VM to destroy or \"all\"")
    parser.add_argument("-v", "--verbose", help="Verbose logs", default=False, action="store_true")
    parser.add_argument("-k", "--keep", help="Keep VMs running", default=False, action="store_true")
    args = parser.parse_args()

    if args.verbose:
        set_log_level(logging.DEBUG)
    log = get_logger("main")

    if args.list or args.destroy:
        images = [f.name for f in os.scandir(CVEX_ROOT) if f.is_dir()]
        if not images:
            log.info("There are no cached VMs")
            sys.exit(0)
        if args.list:
            log.info("Cached VMs:")
        if ROUTER_VM_NAME in images:
            if args.list:
                log.info("%s", ROUTER_VM_NAME)
            if args.destroy == "all" or args.destroy == ROUTER_VM_NAME:
                router = RouterVM()
                router.destroy()
        for image in images:
            if image == ROUTER_VM_NAME:
                continue
            versions = [f.name for f in os.scandir(Path(CVEX_ROOT, image)) if f.is_dir()]
            for version in versions:
                instances = [f.name for f in os.scandir(Path(CVEX_ROOT, image, version)) if f.is_dir()]
                for instance in instances:
                    if args.list:
                        log.info("%s/%s/%s", image, version, instance)
                    if args.destroy == "all" or args.destroy == f"{image}/{version}/{instance}":
                        destination = Path(CVEX_ROOT, image, version, instance)
                        vm = VM([], VMTemplate(
                            f"{image}/{version}/{instance}", "stub", "stub", VMTemplate.VM_TYPE_LINUX), "stub", destination=destination)
                        vm.destroy()
                        try:
                            shutil.rmtree(destination)
                        except:
                            pass
        sys.exit(0)

    output_dir = Path(args.output)
    if not output_dir.exists():
        output_dir.mkdir()
    elif not output_dir.is_dir():
        log.critical("%s is not a directory", output_dir)
        sys.exit(1)

    if not args.cve:
        log.critical("CVE directory is mandatory")
        sys.exit(1)

    # Load cvex.yml of the CVE record
    cvex = CVEX(Path(args.cve))

    # Create VMs
    vms = []
    router = RouterVM(args.keep)
    vms.append(router)
    cve_name = Path(args.cve).name
    for vm_template in cvex.vm_templates:
        if vm_template.vm_type == VMTemplate.VM_TYPE_LINUX:
            vm = LinuxVM(vms, vm_template, cve_name, keep=args.keep)
        elif vm_template.vm_type == VMTemplate.VM_TYPE_WINDOWS:
            vm = WindowsVM(vms, vm_template, cve_name, args.keep)
        else:
            log.critical("VM type is not supported: %r", vm_template.vm_type)
        vms.append(vm)

    # Check that the system has enough free disk space and RAM
    disk_size_needed = REQUIRED_FREE_SPACE   # In gigabytes
    ram_needed = REQUIRED_RAM           # In megabytes
    for vm in vms:
        if vm.vm_name == ROUTER_VM_NAME:
            if not vm.is_created():
                disk_size_needed += LINUX_VAGRANT_BOX_SIZE + ROUTER_VM_SIZE
            ram_needed += LINUX_VM_RAM
        elif vm.vm_type == VMTemplate.VM_TYPE_LINUX:
            if not vm.is_created():
                disk_size_needed += LINUX_VAGRANT_BOX_SIZE + UBUNTU_VM_SIZE
            ram_needed += LINUX_VM_RAM
        elif vm.vm_type == VMTemplate.VM_TYPE_WINDOWS:
            if not vm.is_created():
                disk_size_needed += WINDOWS_VAGRANT_BOX_SIZE + WINDOWS_VM_SIZE
            ram_needed += WINDOWS_VM_RAM
    disk = os.statvfs(Path.home())
    free_space = disk.f_frsize * disk.f_bavail / (1024. ** 3)
    total_ram = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024 ** 2)
    log.debug("Execution of %s requires at least %.2fGB of free disk space and %dMB of RAM",
                    cve_name, disk_size_needed, ram_needed)
    log.debug("Free disk space: %.2fGB, total RAM: %dMB", free_space, total_ram)
    if disk_size_needed > free_space or ram_needed > total_ram:
        log.critical("\x1b[31;1m*************************************************************************\033[0m")
        log.critical("\x1b[31;1mExecution of %s requires at least %.2fGB of free disk space and %dMB of RAM\033[0m",
                        cve_name, disk_size_needed, ram_needed)
        log.critical("\x1b[31;1mFree disk space: %.2fGB, total RAM: %dMB\033[0m", free_space, total_ram)
        log.critical("\x1b[31;1m*************************************************************************\033[0m")

    # Start all VMs
    for vm in vms:
        vm.run()

    # Perform pre-exploitation configuration
    router.set_network_interface_ip(router.ip)
    for vm in vms:
        if vm == router:
            continue
        vm.set_network_interface_ip(router.ip)
        vm.update_hosts(vms)

    # Start network traffic sniffing, mitmproxy, API tracing
    router.start_sniffing(cvex.ports)
    for vm in vms:
        vm.start_api_tracing()

    # Execute commands
    succeed = True
    for vm in vms:
        if vm.command:
            command_idx = 0
            for command in vm.command:
                for vm2 in vms:
                    command = command.replace(f"%{vm2.vm_name}%", vm2.ip)
                command_until = command.split("~~~")
                if len(command_until) == 1:
                    command = command_until[0]
                    until = ""
                else:
                    command, until = command_until
                if command.endswith("&"):
                    is_async = True
                    command = command[:-1]
                else:
                    is_async = False
                # Run strace with the commands, otherwise the Linux agent may detect them too late
                if vm.vm_type == VMTemplate.VM_TYPE_LINUX and vm.trace:
                    r = re.search(vm.trace, command)
                    if r:
                        process_name = r.group(0)
                        path = f"{CVEX_TEMP_FOLDER_LINUX}/{vm.vm_name}_strace_{process_name}_{command_idx}.log"
                        if command.startswith("sudo "):
                            command = f"sudo strace -o {path} {command[5:]}"
                        else:
                            command = f"strace -o {path} {command}"
                try:
                    vm.ssh.run_command(command, is_async=is_async, until=until, show_progress=True)
                except Exception as e:
                    log.critical("Command failed: %r", e)
                    succeed = False
                    break
                command_idx += 1

    # Stop network traffic sniffing, mitmproxy, API tracing
    if succeed:
        for vm in vms:
            vm.stop_api_tracing(args.output)
        router.stop_sniffing(args.output)

    # Stop all VMs
    if not args.keep:
        for vm in vms:
            vm.stop()

    sys.exit(0)


if __name__ == "__main__":
    main()
