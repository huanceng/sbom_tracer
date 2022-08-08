# SBOM Tracer
Make use of the eBPF-based tracing tools [BCC](https://github.com/iovisor/bcc) to trace dependencies during software build.

## Abilities
* Sniff HTTP/1.1 and HTTP/2 to capture download requests sent to GitHub, Gitee, GitLab, etc.
* Trace all git submodules and their corresponding version

## Installing
`bash install.sh`

*SBOM Tracer* is tested on CentOS7 (x86_64, aarch64, vm, docker) by now.

The Linux kernel version of the **docker host** must be higher than 4.17, because [uprobes cannot successfully attach to binaries located in a directory
mounted with overlayfs](https://github.com/torvalds/linux/commit/f0a2aa5a2a406d0a57aa9b320ffaa5538672b6c5).

## Usage
`sbom_tracer -s "your build command" -w "absolute path of the tracer workspace where to save trace results" -k "the absolute path of kernel sources" -t "task id"`

e.g., `sbom_tracer -s "bash build.sh" -w "/tmp/sbom_tracer_workspace" -k "/lib/modules/4.18.0-348.20.1.el7.aarch64/build" -t "example-task-id"`
### Parameters
1. `-s`, `--shell`: the input shell command
2. `-w`, `--workspace`: tracer workspace. If not specified, it will be ~/sbom_tracer_workspace
3. `-k`, `--kernel_source`: the absolute path of kernel sources. If not specified, will try to find kernel sources in /lib/modules/$(uname -r)/build and /usr/src/kernels. See [BCC_KERNEL_SOURCE](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kernel-source-directory) for details
4. `-t`, `--task_id`: task id of a run. If not specified, task id will be the current timestamp

### Run in Docker
To run *SBOM Tracer* in a docker, the docker must be run in **privileged mode**, and it's recommended to mount /src to get proper kernel sources, e.g., 
`docker run -it --privileged -v /usr:/host/usr:ro your_docker_image /bin/bash`

## Output
*SBOM Tracer* will output four logs:
### execsnoop.log
The trace records of *exec() syscalls*, each record consists of the following data:
1. command
2. full command with arguments
3. pid
4. ppid
5. ancestor pids
6. cwd
#### example
`{"full_cmd": "/usr/bin/dirname build.sh", "ppid": 28021, "ancestor_pids": [28022, 28021, 28020, 28019, 28018, 28006, 6811, 2197, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "cmd": "dirname", "pid": 28022, "cwd": "/home/jenkins"}`
### h2sniff.log
The trace records of *HTTP/2*, each record consists of the following data:
1. command
2. pid
3. ppid
4. data
#### example
`{"cmd": "cmake", "pid": 8327, "ppid": 8326, "data": [[":method", "GET"], [":path", "/libjpeg-turbo/libjpeg-turbo/tar.gz/refs/tags/2.0.4"], [":scheme", "https"], [":authority", "codeload.github.com"], ["user-agent", "curl/7.71.1"], ["accept", "*/*"]]}`
### sslsniff.log
The trace records of *HTTP/1.1*, each record consists of the following data:
1. command
2. pid
3. ppid
4. data
#### example
`{"cmd": "cmake", "pid": 9632, "ppid": 27486, "data": "GET /repos/nlohmann/json HTTP/1.1\r\nHost: api.github.com\r\nConnection: keep-alive\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nUser-Agent: python-requests/2.27.1\r\n\r\n"}`
### git_submodule.log
The git submodule info of a git project, each record consists of the following data:
1. commit_id
2. version string
3. remote git url
#### example
`[{"url": "https://gitee.com/mindspore/akg.git\n", "commit_id": "d7dafacb01d0827f0094507dd7f8fd708e90737d", "version_string": "(v1.7.0-106-gd7dafac)"}]`
