from pathlib import Path

CVEX_ROOT = Path.home() / ".cvex"

DEFAULT_PORT = 443

CVEX_FILE = "cvex.yml"

ROUTER_VM_NAME = "router"
ROUTER_VM_DESTINATION = CVEX_ROOT / ROUTER_VM_NAME
ROUTER_VM_IMAGE = "bento/ubuntu-22.04"
ROUTER_VM_VERSION = "202404.23.0"

INIT_SNAPSHOT = "clean"

CVEX_TEMP_FOLDER_LINUX = "/tmp/cvex"
MITMDUMP_LOG = "router_mitmdump.stream"
MITMDUMP_LOG_PATH = f"{CVEX_TEMP_FOLDER_LINUX}/{MITMDUMP_LOG}"
TCPDUMP_LOG = "router_raw.pcap"
TCPDUMP_LOG_PATH = f"{CVEX_TEMP_FOLDER_LINUX}/{TCPDUMP_LOG}"

CVEX_TEMP_FOLDER_WINDOWS = r"C:\cvex"
PROCMON_PML_LOG = "procmon.pml"
PROCMON_XML_LOG = "procmon.xml"

VAGRANT_LOG = "/tmp/vagrant_cvex.log"
