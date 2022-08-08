import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import traceback

from sbom_tracer.local_analyzer.analyzer_factory import AnalyzerFactory
from sbom_tracer.util.common_util import run_daemon, get_command_config, infer_kernel_source_dir
from sbom_tracer.util.const import EXECSNOOP_PATH, H2SNIFF_PATH, SSLSNIFF_PATH, PROJECT_NAME, DEFINITION_FILE_PATTERNS
from sbom_tracer.util.shell_util import execute, execute_recursive


class BccTracer(object):
    def __init__(self, shell, workspace, kernel_source, task_id, shell_path):
        self.shell = shell
        self.workspace = workspace
        self.kernel_source = kernel_source
        self.shell_path = shell_path
        self.task_id = task_id if task_id else str(time.time())
        self.task_workspace = self._init_task_workspace()
        self.combine_shell = "{}_{}.sh".format(self.task_id, PROJECT_NAME)
        self.config = get_command_config()

        self.execsnoop_log = os.path.join(self.task_workspace, "execsnoop.log")
        self.sslsniff_log = os.path.join(self.task_workspace, "sslsniff.log")
        self.h2sniff_log = os.path.join(self.task_workspace, "h2sniff.log")
        self.locally_collected_info_log = os.path.join(self.task_workspace, "locally_collected_info.log")
        self.tar_file = os.path.join(self.task_workspace, "{}_tracer_result.tar.gz".format(self.task_id))

        self.shell_main_pid = None
        self.task_project_dir = None

    def _init_task_workspace(self):
        task_workspace = os.path.join(self.workspace, self.task_id)
        try:
            os.makedirs(task_workspace)
        except OSError:
            pass
        return task_workspace

    def trace(self):
        if not self.init_tracer():
            raise Exception("init tracer exception! please check if bcc is installed successfully")
        shell_exit_status = self.execute_cmd()
        self.stop_trace()
        self.collect_info()
        self.copy_definition_files()
        self.tar()
        return shell_exit_status

    def init_tracer(self):
        try:
            self.run_tracer()
        except Exception as e:
            print("exception occurs when run_tracer: {}".format(str(e)))
            print(traceback.format_exc())
            self.stop_trace()
            return False

        time.sleep(1)
        return True

    def run_tracer(self):
        bcc_python_version = self.infer_bcc_python_version()
        for tool, trace_log in [(EXECSNOOP_PATH, self.execsnoop_log), (SSLSNIFF_PATH, self.sslsniff_log),
                                (H2SNIFF_PATH, self.h2sniff_log)]:
            cmd = "sudo python{} {} --task-id {}".format(bcc_python_version, tool, self.task_id)
            kernel_source = self.kernel_source if self.kernel_source else infer_kernel_source_dir()
            if kernel_source:
                cmd = "sudo BCC_KERNEL_SOURCE={} python{} {} --task-id {}".format(
                    kernel_source, bcc_python_version, tool, self.task_id)
            run_daemon(execute, (cmd,), dict(stdout=open(trace_log, "w"), stderr=subprocess.PIPE))

    @classmethod
    def infer_bcc_python_version(cls):
        if execute("python2 -c '''try:\n from bcc import BPF\nexcept ImportError:\n from bpfcc import BPF'''",
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)[0] == 0:
            return 2
        elif execute("python3 -c '''try:\n from bcc import BPF\nexcept ImportError:\n from bpfcc import BPF'''",
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)[0] == 0:
            return 3
        else:
            raise Exception("can't infer valid bcc python version")

    def execute_cmd(self):
        file_path = os.path.join(self.shell_path, self.combine_shell)
        with open(file_path, "w") as f:
            f.write(self.shell)
        shell_exit_status, _, _ = execute("bash {}".format(self.combine_shell), cwd=self.shell_path)
        shutil.move(file_path, os.path.join(self.task_workspace, self.combine_shell))
        return shell_exit_status

    def stop_trace(self):
        if execute_recursive("ps -ef | grep 'task-id {}' | grep -v \"grep\"".format(self.task_id))[0] != 0:
            return
        execute_recursive("ps -ef | grep 'task-id {}' | grep -v \"grep\" | awk '{{print $2}}' | "
                          "sudo xargs kill -2".format(self.task_id))
        time.sleep(1)

        for _ in range(3):
            if execute_recursive("ps -ef | grep 'task-id {}' | grep -v \"grep\"".format(self.task_id))[0] != 0:
                print("successfully stop tracer with task id: {}".format(self.task_id))
                break
            execute_recursive("ps -ef | grep 'task-id {}' | grep -v \"grep\" | awk '{{print $2}}' | "
                              "sudo xargs kill -9".format(self.task_id))
            time.sleep(1)
        else:
            print("failed to stop tracer with task id: {}".format(self.task_id))

    def collect_info(self):
        if not os.path.isfile(self.execsnoop_log):
            return

        with open(self.execsnoop_log, "r") as f, open(self.locally_collected_info_log, "w") as fw:
            while True:
                line = f.readline().strip()
                if not line:
                    break

                try:
                    cmd_dict = json.loads(line)
                except ValueError:
                    continue

                if not self.is_valid_record(cmd_dict):
                    continue

                if self.combine_shell in cmd_dict["full_cmd"]:
                    self.shell_main_pid = cmd_dict["pid"]
                    self.task_project_dir = cmd_dict["cwd"]

                if self.combine_shell in cmd_dict["full_cmd"] or self.shell_main_pid in cmd_dict["ancestor_pids"]:
                    if cmd_dict["cmd"] in self.config:
                        self.analyze_executed_command(cmd_dict["cmd"], cmd_dict["full_cmd"], cmd_dict["cwd"], fw)

    @classmethod
    def is_valid_record(cls, cmd_dict):
        return all(cmd_dict.get(k) for k in ("pid", "ppid", "cmd", "full_cmd", "ancestor_pids"))

    @classmethod
    def analyze_executed_command(cls, cmd, full_cmd, cwd, fd):
        for analyzer in AnalyzerFactory.get_all_analyzers():
            analyzer().analyze(cmd, full_cmd, cwd, fd)

    def copy_definition_files(self):
        for filename in os.listdir(self.task_project_dir):
            for pattern in DEFINITION_FILE_PATTERNS:
                if re.match(pattern, filename):
                    shutil.copy(os.path.join(self.task_project_dir, filename), self.task_workspace)

    def tar(self):
        os.mknod(self.tar_file)
        tar_file = tarfile.open(self.tar_file, "w:gz")
        for filename in os.listdir(self.task_workspace):
            tar_file.add(os.path.join(self.task_workspace, filename), arcname=filename)
        tar_file.close()
