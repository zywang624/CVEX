import re
import sys
import tempfile
import procmon_parser
import time

from cvex.consts import *
from cvex.vm import VM, VMTemplate


class WindowsVM(VM):
    def __init__(self,
                 vms: list,
                 template: VMTemplate,
                 cve: str,
                 keep: bool = False,
                 new: bool = False):
        super().__init__(vms, template, cve, keep=keep, new=new)

    def init(self, router: VM | None = None):
        self.playbooks.insert(0, Path(Path(__file__).parent.parent.parent, "ansible", "windows.yml"))

    def update_hosts(self, vms: list[VM]):
        remote_hosts = "/C:\\Windows\\System32\\drivers\\etc\\hosts"
        local_hosts = tempfile.NamedTemporaryFile()
        self.ssh.download_file(local_hosts.name, remote_hosts)
        with open(local_hosts.name, "r") as f:
            hosts = f.read()
        ips = "\r\n"
        for vm in vms:
            if vm != self:
                line = f"{vm.ip} {vm.vm_name}\r\n"
                if line not in hosts:
                    ips += line
        if ips != "\r\n":
            self.log.debug("Setting ip hosts: %s", ips)
            hosts += ips
            with open(local_hosts.name, "w") as f:
                f.write(hosts)
            self.ssh.upload_file(local_hosts.name, remote_hosts)

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

    def get_ansible_inventory(self) -> Path:
        inventory = Path(self.destination, "inventory.ini")
        with open(inventory, "w") as f:
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
            f.write(data)
        return inventory

    def set_network_interface_ip(self, router_ip: str):
        netsh_interface = self.ssh.run_command("netsh interface ipv4 show inter")
        id = re.search(r"(\d+).+?Ethernet 2", netsh_interface)
        if not id:
            self.log.critical("'netsh interface ipv4 show inter' returned unknown data:\n%s", netsh_interface)
            sys.exit(1)
        id = id.group(1)
        # Prevents activation of "Autoconfiguration IPv4 Address"
        self.ssh.run_command(f"netsh interface ipv4 set interface {id} dadtransmits=0 store=persistent")
        # Sometimes it exits with "Access denied" even though the IP sets up successfully
        try:
            self.ssh.run_command((f"powershell \""
                                f"Get-NetAdapter -Name 'Ethernet 2' | "
                                f"New-NetIPAddress -IPAddress {self.ip} -DefaultGateway {router_ip} -PrefixLength 24\""))
        except:
            pass
        try:
            self.ssh.run_command("powershell \"Disable-NetAdapter -Name 'Ethernet 2' -Confirm:$False\"")
        except:
            pass
        try:
            self.ssh.run_command("powershell \"Enable-NetAdapter -Name 'Ethernet 2' -Confirm:$False\"")
        except:
            pass
        self.ssh.run_command("route DELETE 192.168.56.0")
        route_print = self.ssh.run_command("route print")
        id = re.search(r"(\d+)\.\.\.([0-9a-fA-F]{2} ){6}\.\.\.\.\.\.Intel\(R\) PRO/1000 MT Desktop Adapter #2",
                       route_print)
        if not id:
            self.log.critical("'route print' returned unknown data:\n%s", route_print)
            sys.exit(1)
        id = id.group(1)
        self.ssh.run_command(f"route ADD 192.168.56.0 MASK 255.255.255.0 {router_ip} if {id}")

    def start_api_tracing(self):
        try:
            self.ssh.run_command("taskkill /IM Procmon.exe /F")
        except:
            pass
        try:
            self.ssh.run_command(f"rmdir /S /Q {CVEX_TEMP_FOLDER_WINDOWS}")
        except:
            pass
        try:
            self.ssh.run_command(f"mkdir {CVEX_TEMP_FOLDER_WINDOWS}")
        except:
            pass

        pml_log = f"{CVEX_TEMP_FOLDER_WINDOWS}\\{self.vm_name}_{PROCMON_PML_LOG}"
        if self.trace:
            remote_config_path = f"{CVEX_TEMP_FOLDER_WINDOWS}\\config.pmc"
            with open(Path(Path(__file__).parent.parent.parent, "data", "procmon.pmc"), "rb") as f:
                config = procmon_parser.load_configuration(f)
            config["FilterRules"] = [
                procmon_parser.Rule(
                    procmon_parser.Column.PROCESS_NAME,
                    procmon_parser.RuleRelation.CONTAINS,
                    self.trace,
                    procmon_parser.RuleAction.INCLUDE)]
            local_config = tempfile.NamedTemporaryFile()
            with open(local_config.name, "wb") as f:
                procmon_parser.dump_configuration(config, f)
            self.ssh.upload_file(local_config.name, f"/{remote_config_path}")
            self.ssh.run_command(
                f"C:\\Tools\\Procmon64.exe /AcceptEula /BackingFile {pml_log} /LoadConfig {remote_config_path} /Quiet",
                is_async=True)
        else:
            self.ssh.run_command(
                f"C:\\Tools\\Procmon64.exe /AcceptEula /BackingFile {pml_log} /Quiet",
                is_async=True)

    def stop_api_tracing(self, output_dir: str):
        self.ssh.run_command("C:\\Tools\\Procmon64.exe /AcceptEula /Terminate")
        pml_log = f"{CVEX_TEMP_FOLDER_WINDOWS}\\{self.vm_name}_{PROCMON_PML_LOG}"
        xml_log = f"{CVEX_TEMP_FOLDER_WINDOWS}\\{self.vm_name}_{PROCMON_XML_LOG}"
        self.ssh.run_command(
            f"C:\\Tools\\Procmon64.exe /AcceptEula /OpenLog {pml_log} /SaveAs {xml_log}")
        self.ssh.download_file(f"{output_dir}/{self.vm_name}_{PROCMON_PML_LOG}", f"/{pml_log}")
        self.ssh.download_file(f"{output_dir}/{self.vm_name}_{PROCMON_XML_LOG}", f"/{xml_log}")
