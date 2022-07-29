#!/usr/bin/env python
import os
import platform
import sys
import traceback

import click

from sbom_tracer.tracer.bcc_tracer import BccTracer


@click.command()
@click.option("--shell", "-s", help="the input shell command, e.g., 'sh build.sh'")
@click.option("--workspace", "-w", help="tracer workspace. If not specified, it will be ~/sbom_tracer_workspace")
@click.option("--kernel_source", "-k", help="the absolute path of kernel sources. If not specified, "
                                            "BCC will try to find kernel sources in /lib/modules/$(uname -r)/build")
@click.option("--task_id", "-t", help="task id of a run. If not specified, task id will be the current timestamp")
def main(shell, workspace, kernel_source, task_id):
    if not shell:
        click.echo("please input a shell command, such as 'sh build.sh'")
        sys.exit(1)
    if not workspace:
        workspace = os.path.join(os.path.expanduser("~"), "sbom_tracer_workspace")

    if platform.uname()[0] != "Linux":
        click.echo("sbom_tracer is only supported in Linux")
        sys.exit(1)

    try:
        status = BccTracer(shell, workspace, kernel_source, task_id, os.getcwd()).trace()
        sys.exit(status)
    except Exception as e:
        click.echo("exception occurs: {}".format(str(e)))
        click.echo(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
