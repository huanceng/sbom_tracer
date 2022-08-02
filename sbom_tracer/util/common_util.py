import os
import time
from threading import Thread

import yaml

from sbom_tracer.util.const import DEFAULT_COMMAND_CONFIG


def run_daemon(target, args, kwargs):
    thread = Thread(target=target, args=args, kwargs=kwargs)
    thread.daemon = True
    thread.start()

    time.sleep(1)
    if not thread.is_alive():
        raise Exception("failed to run command as daemon")


def get_command_config():
    with open(DEFAULT_COMMAND_CONFIG, "r") as f:
        return yaml.safe_load(f)


def infer_kernel_source_dir():
    link_path = "/lib/modules/{}/build".format(os.uname()[2])
    if os.path.isdir(link_path):
        return link_path
    kernel_home = "/usr/src/kernels"
    if not os.path.isdir(kernel_home):
        return None
    if not os.listdir(kernel_home):
        return None
    return os.path.join(kernel_home, sorted(os.listdir(kernel_home), reverse=True)[0])
