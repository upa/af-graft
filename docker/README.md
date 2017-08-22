# AF_GRAFT docker containers

## Build docker images

The `af-graft/docker` directory contains Dockerfile(s) for testing
AF_GRAFT in docker container environments. `graft` is a simple
container including AF_GRAFT userland suites and useful utilities
(iperf3, netperf, ping and vim).

```shell-session
$ git clone https://github.com/upa/af-graft.git
$ cd af-graft/docker/graft
$ docker build -t af-graft .
Sending build context to Docker daemon   2.56kB
Step 1/7 : FROM ubuntu:latest
 ---> d355ed3537e9

# Note that building af_graft.ko in this docker build process fails, but,
# in containers, the kernel module is not required in containers. Only
# ip graft command is necessary.
#
# ...snipped...

Successfully tagged af-graft:latest
$ docker images | grep graft
af-graft               latest              43ac9aed3d02        21 seconds ago      495MB
```

To create AF_GRAFT sockets from containers, host OS must support
AF_GRAFT. Install af_graft.ko before executing containers.

Then, executing iperf3 onto host OS loopback interface.
```shell-session

$ docker run -it --cap-add=NET_ADMIN -e GRAFT_CONV_PAIRS="0.0.0.0:5201=ep-lo" af-graft bash -c "ip gr add ep-lo type ipv4 addr 127.0.0.1 port 5201 && iperf3 -s"
libgrwrap.so:208:socket(): overwrite family 10 with AF_GRAFT (4)
libgrwrap.so:319:setsockopt(): wrap setsockopt() level=1, optname=2
warning: this system does not seem to support IPv6 - trying IPv4
libgrwrap.so:208:socket(): overwrite family 2 with AF_GRAFT (4)
libgrwrap.so:319:setsockopt(): wrap setsockopt() level=1, optname=2
libgrwrap.so:298:bind(): convert bind 0.0.0.0:5201 to ep-lo
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------


```

Containers require NET_ADMIN capability to add graft end points in
containers' network namespaces.
