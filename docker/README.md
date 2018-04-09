
## AF_GRAFT docker containers (for test)

This directory contains Dockerfile(s) for testing AF_GRAFT in docker
containers. `graft` is a simple container including AF_GRAFT userland
suites and useful utilities (iperf3, netperf, ping, and vim). `nginx`
is a simple container including AF_GRAFT and nginx.


### `graft` docker image

```shell-session
$ cd af-graft/docker/graft
$ docker build -t af-graft .
Sending build context to Docker daemon   2.56kB
Step 1/7 : FROM ubuntu:latest
 ---> d355ed3537e9

# ...snipped...

Successfully tagged af-graft:latest
$ docker images | grep graft
af-graft               latest              43ac9aed3d02        21 seconds ago      495MB
```

To create AF_GRAFT sockets from containers, host OS must support
AF_GRAFT. Install af_graft.ko before executing containers.


The example shown below executes an iperf3 server process in the
container. The original TCP socket (0.0.0.0:5201 in the container) is
overridden and grafted onto 127.0.0.1:5201 in the host network stack.

```shell-session
$ docker run -it --cap-add=NET_ADMIN -e GRAFT_CONV_PAIRS="0.0.0.0:5201=ep-lo" af-graft bash -c "ip gr add ep-lo type ipv4 addr 127.0.0.1 port 5201 && iperf3 -s"
libgraft-hijack.so:466:socket(): overwrite family 10 with AF_GRAFT (4)
libgraft-hijack.so:597:setsockopt(): wrap setsockopt() level=1, optname=2
libgraft-hijack.so:531:bind(): no matched ep for fd=4, :::5201
warning: this system does not seem to support IPv6 - trying IPv4
libgraft-hijack.so:466:socket(): overwrite family 2 with AF_GRAFT (4)
libgraft-hijack.so:597:setsockopt(): wrap setsockopt() level=1, optname=2
libgraft-hijack.so:540:bind(): convert bind 0.0.0.0:5201 to ep-lo
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------

```

Note that containers require NET_ADMIN capability to add graft
endpoints in containers' network namespaces. We plane to remove this
vulnerable state by integrating AF_GRAFT into docker.



### `nginx` docker image

To build the nginx docker image, `docker build -t af-graft-nginx .` in
af-graft/docker/nginx directory. 

```shell-session
$ cd af-graft/docker/nginx
$ docker build -t af-graft-nginx .


$ docker run -it --cap-add=NET_ADMIN -v `pwd`/default:/etc/nginx/sites-enabled/default af-graft-nginx bash -c "ip gr add nx4 type ipv4 addr 0.0.0.0 port 8080 && nginx -g 'daemon off;'"
```

The nginx process creates an AF_INET socket and binds it to 0.0.0.0:80
in the container, but the socket is converted to AF_GRAFT and grafted
onto 0.0.0.0:80 of the host network stack.

It brings the same result with `docker run -p 80:8080` from the
viewpoint of exchanged data in HTTP. However, in the case of the use
of AF_GRAFT, the nginx process directly utilizes the host network
stack while maintaining the netns separation. As a result, throughput
and latency are improved by bypassing the container's network stack.