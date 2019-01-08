


This document describes how to use AF_GRAFT with docker as is with
minimum effort.

First, prepare a docker image that is capable of AF_GRAFT.
1. docker pull upaa/graft-demo
2. cd af-graft/docker/demo && ./build-image.sh [container name] after make

Both images are identical.


## 1. Prepare a network namespace for graft endpoints

Create a docker container that is used as just a network namespace for
other containers where applications run. This is similar to _Pod_ in
kubernetes.


```shell-session
$ docker run --net=none -d -it --name net1 ubuntu bash
```

This creates a container named `net1`. This container only contains
graft endpoints on its network namespace. Thus, any interfaces,
addresses, and connectivity are unnecessary. --net=none just creates
separated network namespace and configures nothing.



## 2. Setup graft endpoints on the network namespace

Next step is to prepare graft endpoints on the net1. To do this, you
can use `docker-ns-exec` command that is installed by AF_GRAFT.
docker-ns-exec allows us to execute arbitrary commands in specified
network namespaces of containers.


Let's add graft endpoints into the net1 container using docker-ns-exec.
```shell-session
$ sudo docker-ns-exec net1 /sbin/ip graft add ep-in4 type ipv4 addr 127.0.0.1 port 8080 netns 1
$ sudo docker-ns-exec net1 /sbin/ip graft add ep-in6 type ipv6 addr ::1 port 8080 netns 1

$ sudo docker-ns-exec net1 ip graft show
ep-in4 type ipv4 addr 127.0.0.1 port 8080 netns 1 
ep-in6 type ipv6 addr ::1 port 8080 netns 1
```

`netns 1` of `ip graft add` indicates the actual endpoints are in the
default network namespace (netns of pid 1). An AF_GRAFT socket
assigned to ep-in4 on this namespace, the socket is grafted onto the
socket opened on 127.0.0.1:8080 in host network stack across network
namespace boundary.



## 3. Run applications with AF_GRAFT in containers

It is ready to run the graft-demo container. The graft-demo container
image is configured to use conversion mapping listed below:

- Server-side sockets (bind(), listen(), and accept())
    - use ep-in4 for INADDR_ANY (0.0.0.0) with port number 0 to 65535
    - use ep-in6 for in6addr_any (0::0) with port number 0 to 65535
- Client-side sockets (connect(), sendto(),  and sendmsg())
    - use ep-out4 for any IPv4 destinations (0.0.0.0/0)
    - use ep-out6 for any IPv6 destinations (0::0/0)


We prepared ep-in4 and ep-in6 at the last step, so we can run server
applications like:

```shell-session
$ docker run -it --net=container:net1 upaa/graft-demo iperf3 -s -4 
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------
```

--net=container:net1 indicates this container shares the network
namespace with the net1 container that has the graft endpoints.  The
iperf3 server process try to bind() the socket to 0.0.0.0:5201 by
default, and it is converted into ep-in4. The socket bind()ed to the
ep-in4 is grafted onto 0.0.0.0:8080 at the host network stack. This is
socket-grafting.


Another example is to run nginx web server using AF_GRAFT:

```shell-session
$ docker run -it --net=container:net1 upaa/graft-demo nginx -g "daemon off;"
```


The nginx process opens two sockets and bind() them to 0.0.0.0:80 and
[::]:80. Both bind() are converted into ep-in4 and ep-in6, and grafted
onto the host network stack. So, you can access the nginx directly
across network namespace boundary, without NAT, veth, and network
stack processing at the container network stack.

```shell-session
$ telnet localhost 8080
Trying ::1...
Connected to localhost.
Escape character is '^]'.
GET /
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>

...
```


## 4. Modify container images

af-graft/docker/demo/Dockerfile is the Dockerfile of the graft-demo
image. The important part of the AF_GRAFT-capable docker image is:

```
# setup AF_GRAFT
COPY ./libgraft-convert.so /usr/local/lib/
COPY ./graft /usr/local/bin/

ENTRYPOINT [ "/usr/local/bin/graft",            \
                "-i", "0.0.0.0:0-65535=ep-in4", \
                "-i", ":::0-65535=ep-in6",      \
                "-e", "0.0.0.0/0=ep-out4",      \
                "-e", "::/0=ep-out6"    \
        ]
```

You can change graft endpoint names and conversion configuration by
modifying the ENTRYPOINT part as you like.



## Note

### Why the net1 container is needed

A reasonable way to configure graft endpoints in the docker semantics
is to setup graft endpoints when the container is created, so then
applications on the containers can use the graft endpoints on their
network namespaces. But, to do this, we need to modify docker itself,
and it is difficult...

Preparing a separated network namespace with a docker container for
maintaining graft endpoints like the net1 container described above
enables us to play AF_GRAFT without such significant effort to modify
docker itself or implementing complicated network plugins.



### How much does socket-grafting improve network performance

Please see the paper [Grafting sockets for fast container
networking](https://dl.acm.org/citation.cfm?id=3230723).