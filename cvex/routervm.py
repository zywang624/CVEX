import threading
import time
import fabric

from cvex.consts import *
from cvex.logger import get_logger
from cvex.vm import VMTemplate
from cvex.linuxvm import LinuxVM


class RouterVM(LinuxVM):
    def __init__(self, keep: bool = False):
        template = VMTemplate(ROUTER_VM_NAME,
                              ROUTER_VM_IMAGE,
                              ROUTER_VM_VERSION,
                              VMTemplate.VM_TYPE_LINUX)
        super().__init__([], template, ROUTER_VM_NAME, destination=ROUTER_VM_DESTINATION, keep=keep)

    def init(self):
        self.log.info("Initializing the router VM")
        self.ssh.run_command("wget https://downloads.mitmproxy.org/10.3.1/mitmproxy-10.3.1-linux-x86_64.tar.gz")
        self.ssh.run_command("sudo tar -xf mitmproxy-10.3.1-linux-x86_64.tar.gz -C /usr/bin")
        self.ssh.run_command("mitmdump --mode transparent", is_async=True, until="Transparent Proxy listening at")
        self.ssh.run_command("pkill mitmdump")
        self.ssh.upload_file("data/certindex", "certindex")
        self.ssh.upload_file("data/default.cfg", "/home/vagrant/.mitmproxy/default.cfg")
        self.ssh.run_command(f"openssl ca -config /home/{self.vag.user()}/.mitmproxy/default.cfg -gencrl -inform PEM -keyfile /home/{self.vag.user()}/.mitmproxy/mitmproxy-ca.pem -cert /home/{self.vag.user()}/.mitmproxy/mitmproxy-ca-cert.pem -out /home/{self.vag.user()}/.mitmproxy/root.crl.pem")
        self.ssh.run_command(f"openssl crl -inform PEM -in /home/{self.vag.user()}/.mitmproxy/root.crl.pem -outform DER -out /home/{self.vag.user()}/.mitmproxy/root.crl")

    def _read_output(self, runner: fabric.runners.Remote):
        try:
            stdouts = 0
            while True:
                if runner.channel.closed:
                    return
                new_stdouts = len(runner.stdout)
                if new_stdouts > stdouts:
                    for i in range(stdouts, new_stdouts):
                        self.log.debug(runner.stdout[i])
                stdouts = new_stdouts
                time.sleep(0.1)
        except:
            return

    def start_sniffing(self, ports: list[int]):
        try:
            self.ssh.run_command("pkill mitmdump")
        except:
            pass
        try:
            self.ssh.run_command("sudo pkill tcpdump")
        except:
            pass
        try:
            self.ssh.run_command(f"rm -rf {CVEX_TEMP_FOLDER_LINUX}")
        except:
            pass
        self.ssh.run_command(f"mkdir {CVEX_TEMP_FOLDER_LINUX}")
        self.ssh.run_command("sudo sysctl net.ipv4.ip_forward=1")
        self.tcpdump_runner = self.ssh.run_command(
            f"sudo tcpdump -i eth1 -U -w {TCPDUMP_LOG_PATH}", is_async=True)
        self.tcpdump_thread = threading.Thread(target=self._read_output, args=[self.tcpdump_runner])
        self.tcpdump_thread.start()
        for port in ports:
            self.ssh.run_command(
                f"sudo iptables -t nat -I PREROUTING --src 0/0 --dst 0/0 -p tcp --dport {port} -j REDIRECT --to-ports 8080")
        self.mitmdump_runner = self.ssh.run_command(
            f"mitmdump --mode transparent -k --set block_global=false -w {MITMDUMP_LOG_PATH}",
            is_async=True, until="Transparent Proxy listening at")
        self.mitmdump_thread = threading.Thread(target=self._read_output, args=[self.mitmdump_runner])
        self.mitmdump_thread.start()

    def stop_sniffing(self, output_dir: str):
        self.ssh.send_ctrl_c(self.tcpdump_runner)
        self.ssh.send_ctrl_c(self.mitmdump_runner)

        self.log.info("Wait for 5 seconds to let tcpdump and mitmdump flush logs on disk...")
        time.sleep(5)

        self.tcpdump_thread.join()
        self.mitmdump_thread.join()

        self.ssh.download_file(f"{output_dir}/{TCPDUMP_LOG}", TCPDUMP_LOG_PATH)
        self.ssh.download_file(f"{output_dir}/{MITMDUMP_LOG}", MITMDUMP_LOG_PATH)
