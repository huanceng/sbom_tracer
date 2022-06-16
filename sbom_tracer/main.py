#!/usr/bin/env python
import os
import platform
import sys
import traceback

import click

from sbom_tracer.tracer.bcc_tracer import BccTracer


@click.command()
@click.option("--shell", "-s", help="the input shell command, e.g., 'sh build.sh'")
@click.option("--workspace", "-w", help="tracer workspace, default is ~/sbom_tracer_workspace")
def main(shell, workspace):
    if not shell:
        click.echo("please input a shell command, such as 'sh build.sh'")
        sys.exit(1)
    if not workspace:
        workspace = os.path.join(os.path.expanduser("~"), "sbom_tracer_workspace")

    if platform.uname()[0] != "Linux":
        click.echo("sbom_tracer is only supported in Linux")
        sys.exit(1)

    try:
        status = BccTracer(shell=shell, workspace=workspace, shell_path=os.getcwd()).trace()
        sys.exit(status)
    except Exception as e:
        click.echo("exception occurs: {}".format(str(e)))
        click.echo(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
