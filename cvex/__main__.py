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

    def __init__(self, cve: str):
        self.log = get_logger("CVEX")

        cvex_yml = Path("records", cve, CVEX_FILE)
        if not cvex_yml.exists():
            self.log.critical("%s does not exist", cvex_yml)
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

        blueprint_yml = Path("blueprints", cvex['blueprint'], "blueprint.yml")
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
                playbooks.append(Path("blueprints", cvex['blueprint'], data['playbook']))
            if vm_name not in cvex:
                self.log.critical("%s: configuration mismatch", cvex_yml)
                sys.exit(1)
            if 'trace' in cvex[vm_name]:
                trace = cvex[vm_name]['trace']
            else:
                trace = None
            if 'playbook' in cvex[vm_name]:
                playbooks.append(Path("records", cve, cvex[vm_name]['playbook']))
            if 'command' in cvex[vm_name]:
                command = cvex[vm_name]['command']
                if type(command) == str:
                    command = [command]
            else:
                command = None
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
    parser.add_argument("-c", "--cve", help="CVE name in format 'CVE-XXXXXX-XX'")
    parser.add_argument("-o", "--output", help="Directory for generated logs", default="out")
    parser.add_argument("-l", "--list", help="List all cached VMs", default=False, action="store_true")
    parser.add_argument("-d", "--destroy", help="Destroy cached VMs (destroy all if empty)")
    parser.add_argument("-v", "--verbose", help="Verbose logs", default=False, action="store_true")
    parser.add_argument("-k", "--keep", help="Keep VMs running", default=False, action="store_true")
    args = parser.parse_args()

    if args.verbose:
        set_log_level(logging.DEBUG)
    log = get_logger("main")

    if args.list or args.destroy != None:
        images = [f.name for f in os.scandir(CVEX_ROOT) if f.is_dir()]
        if not images:
            log.info("There are no cached VMs")
            sys.exit(0)
        if args.list:
            log.info("Cached VMs:")
        if ROUTER_VM_NAME in images:
            if args.list:
                log.info("%s", ROUTER_VM_NAME)
            if args.destroy == "" or args.destroy == ROUTER_VM_NAME:
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
                    if args.destroy == "" or args.destroy == f"{image}/{version}/{instance}":
                        destination = Path(CVEX_ROOT, image, version, instance)
                        vm = VM([], VMTemplate("stub", "stub", "stub", VMTemplate.VM_TYPE_LINUX), "stub", destination=destination)
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

    if args.cve is None:
        log.critical("CVE number is mandatory")
        sys.exit(1)

    # Load cvex.yml of the CVE record
    cvex = CVEX(args.cve)

    # Start all VMs
    vms = []
    router = RouterVM(args.keep)
    router.run()
    vms.append(router)
    for vm_template in cvex.vm_templates:
        if vm_template.vm_type == VMTemplate.VM_TYPE_LINUX:
            vm = LinuxVM(vms, vm_template, args.cve, keep=args.keep)
            vm.run(router)
        elif vm_template.vm_type == VMTemplate.VM_TYPE_WINDOWS:
            vm = WindowsVM(vms, vm_template, args.cve, args.keep)
            vm.run(router)
        vms.append(vm)

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
                # Run strace with the commands so that the Linux agent
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
                    vm.ssh.run_command(command, is_async=is_async, until=until)
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
