import os

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROJECT_NAME = os.path.basename(PROJECT_DIR)
DEFAULT_COMMAND_CONFIG = os.path.join(PROJECT_DIR, "conf/default_command_config.yml")

SSLSNIFF_PATH = os.path.join(PROJECT_DIR, "bcc/sslsniff.py")
H2SNIFF_PATH = os.path.join(PROJECT_DIR, "bcc/h2sniff.py")
EXECSNOOP_PATH = os.path.join(PROJECT_DIR, "bcc/execsnoop.py")

DEFINITION_FILE_PATTERNS = [r".*requirements.*\.txt"]
