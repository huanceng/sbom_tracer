import json
import os
import subprocess

from sbom_tracer.local_analyzer.analyzer_base import AnalyzerBase
from sbom_tracer.util.shell_util import execute


class GitSubmoduleAnalyzer(AnalyzerBase):
    def __init__(self):
        super(GitSubmoduleAnalyzer, self).__init__("git", r"submodule\s*(update|init)", "git_submodule")

    def _analyze(self, cmd, full_cmd, cwd, fd):
        try:
            os.chdir(cwd)
            out = execute("git submodule status --recursive", stdout=subprocess.PIPE, stderr=subprocess.PIPE)[1]
            submodules = out.strip().split("\n")
            for submodule in submodules:
                if not submodule or submodule.startswith("-"):
                    continue
                commit_id, package_name, version_string = submodule.strip().split()
                os.chdir(os.path.join(cwd, package_name))
                url = execute(
                    "git config --get remote.origin.url", stdout=subprocess.PIPE, stderr=subprocess.PIPE)[1].strip()
                fd.write(json.dumps(dict(commit_id=commit_id, version_string=version_string, url=url, tag=self.tag))
                         + "\n")
        except:
            pass
