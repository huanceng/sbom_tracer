import shlex
import subprocess

import six
from six.moves import range

from sbom_tracer.util.compat import batch_decode


def execute_recursive(cmd):
    try:
        if not isinstance(cmd, (str, six.text_type)):
            return 1, "", ""

        cmds = cmd.split("|")
        former_out = None
        p = None
        for i in range(len(cmds)):
            p = subprocess.Popen(shlex.split(cmds[i]), stdin=former_out, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True)
            if p is None:
                return 1, "", ""
            former_out = p.stdout

        out, err = batch_decode(p.communicate())
        return p.returncode, out, err
    except Exception as e:
        return 1, "", str(e)


def execute(cmd, **kwargs):
    try:
        if not isinstance(cmd, (str, six.text_type)):
            return 1, "", ""

        p = subprocess.Popen(shlex.split(cmd), close_fds=True, **kwargs)
        if p is None:
            return 1, "", ""

        out, err = batch_decode(p.communicate())
        return p.returncode, out, err
    except Exception as e:
        return 1, "", str(e)
