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

[Install](https://cloudbytes.dev/snippets/upgrade-python-to-latest-version-on-ubuntu-linux) Python 3.10 or higher.

### Create virtual environment
```
sudo apt install python3.12-venv
cd C2F2
python3.12 -m venv venv
source venv/bin/activate
```

### Install Python dependecies
```
pip install -e .
```

### Install VirtualBox

While in theory Vagrant should work with any VM provider, CVEX was tested only with VirtualBox. Install VirtualBox this way:
```
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack
```

## Run

CVEX comes with a set of PoC CVEs:
- [CVE-000000-00](records/CVE-000000-00): curl, executed on Windows, downloads a web-page from ngix, running on Ubuntu
- [CVE-000000-01](records/CVE-000000-01): curl, executed on Ubuntu, downloads a web-page from ngix, running on another Ubuntu
- [CVE-000000-02](records/CVE-000000-02): curl, executed on Ubuntu, downloads a web-page from ngix, running on Windows
- [CVE-000000-03](records/CVE-000000-03): curl, executed on Windows, downloads a web-page from ngix, running on another Windows

Let's take CVE-000000-00 as an example. [records/CVE-000000-00/cvex.yml](records/CVE-000000-00/cvex.yml) describes the VM infrastructure that allows reproducing this CVE:
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
  command: ...   # Command to execute on this VM (optional); %vm_name% will be replaced with the IP address of the VM
...:
  trace: ...
  playbook: ...
  command: ...
...
```

CVEX blueprints define minimal network deployments:
- Ubuntu host attacking Window host
- Window host attacking Ubuntu host
- Ubuntu host attacking multiple Windows hosts
- ...

Contributors can provide additional blueprints. In the case of CVE-000000-00 the blueprint `windows10-ubuntu2204` is stored in [/blueprint/windows10-ubuntu2204/blueprint.yml](/blueprint/windows10-ubuntu2204/blueprint.yml):
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
$ python3 -m cvex -c CVE-000000-00
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
$ python3 -m cvex -c CVE-000000-00 -k
2024-09-13 14:25:18,880 - INFO - [router] Retrieving status of router...
2024-09-13 14:25:23,828 - INFO - [router] VM router (192.168.56.2) is already running
2024-09-13 14:25:26,910 - INFO - [router] Retrieving snapshot list of router...
2024-09-13 14:25:29,701 - INFO - [windows] Looking for a VM with CVE-000000-00/windows snapshot...
2024-09-13 14:25:35,875 - INFO - [windows] Retrieving status of windows...
2024-09-13 14:25:41,071 - INFO - [windows] VM windows (192.168.56.3) is already running
2024-09-13 14:25:45,390 - INFO - [windows] Retrieving snapshot list of windows...
2024-09-13 14:25:51,738 - INFO - [windows] Creating snapshot 'clean' for VM windows (192.168.56.3)...
```

CVEX runs the [ansible/windows.yml](/ansible/windows.yml) Ansible script before creating the `CVE-000000-00/windows` snapshot:
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
2024-09-13 14:36:32,194 - INFO - [windows] Creating snapshot 'CVE-000000-00/windows' for VM windows (192.168.56.3)...
```

After the Windows VM, CVEX runs the Ubuntu VM:
```
2024-09-13 14:37:03,308 - INFO - [ubuntu] Looking for a VM with CVE-000000-00/ubuntu snapshot...
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

[records/CVE-000000-00/cvex.yml](records/CVE-000000-00/cvex.yml) has an optional parameter `playbook: linux.yml` that specifies the custom Ansible playbook. In our case it installs nginx before creating the `CVE-000000-00/ubuntu` snapshot:
```
2024-09-13 14:41:35,241 - INFO - [ubuntu] Executing Ansible playbook records/CVE-000000-00/linux.yml...
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
2024-09-13 14:42:51,776 - INFO - [ubuntu] Creating snapshot 'CVE-000000-00/ubuntu' for VM ubuntu (192.168.56.4)...
```

Every VM may have maximum 3 Ansible playbooks:
1. Configuration playbook ([ansible/linux.yml](/ansible/linux.yml)) - controlled by CVEX developers
2. Blueprint playbook (none in our case) - controlled by CVEX blueprint contributors
3. CVE playbook ([records/CVE-000000-00/linux.yml](records/CVE-000000-00/linux.yml)) - controlled by CVEX users

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

