import logging
import signal
import time

import fabric
import paramiko
import vagrant

from cvex.logger import get_logger


class SSH:
    log: logging.Logger
    ssh: fabric.Connection

    def __init__(self, vm: vagrant.Vagrant, vm_name: str):
        self.log = get_logger(vm_name)
        self.ssh = self._ssh_connect(vm)

    def _ssh_connect(self, vm: vagrant.Vagrant) -> fabric.Connection:
        self.log.debug("Retrieving SSH configuration...")
        hostname = vm.hostname()
        port = vm.port()
        username = vm.user()
        key_filename = vm.keyfile()
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

    def run_command(self, command: str, is_async: bool = False, until: str = "") -> str | fabric.runners.Remote:
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
