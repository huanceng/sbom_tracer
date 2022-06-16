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
