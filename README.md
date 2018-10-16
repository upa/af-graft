
AF_GRAFT
========

## What is this

This is a new socket address family for containers. AF_GRAFT sockets
can be _grafted_ onto other address family sockets _across netns
separation_.

By using AF\_GRAFT, applications can utilize host network stacks
directly bypassing container network stacks. This mechanism improves
throughput and latency of containerized applications.

The detail is described in the paper [Grafting sockets for fast
container networking](https://dl.acm.org/citation.cfm?id=3230723).


## Quick start

We tested AF\_GRAFT on Ubuntu 16.04, Linux kernel 4.4.0-83-generic.

### Compile

```shell-session
$ git clone https://github.com/upa/af-graft.git
$ cd af-graft
$ make
$ insmod kmod/af_graft.ko
```

Note that the current implementation overrides AF_IPX with AF_GRAFT
because Linux kernel prohibits dynamically adding a new address family
number.

```
sudo insmod af_graft.ko insmod: ERROR: could not insert module
af_graft.ko: File exists
```

So, the error above indicates that a socket protocol family is already
registered in the address family number, which is AF_IPX. In this
case, please rmmod the ipx kernel module.



### Endpoint

AF_GRAFT uses _Endpoints_ to specify which AF_GRAFT sockets to be
grafted onto which sockets. Endpoints are the same as the _names_ of
the bind() semantics: IP addresses and ports for AF_INET and AF_INET6
sockets, and file system paths for AF_UNIX. As well as such AFs,
AF_GRAFT has its endpoints (graft endpoints). Each graft endpoint,
which is identified by an arbitrary string, is associated with other
AF endpoints.

A modified iproute2 package contained in this repository can configure
graft endpoints.

```shell-session
$ ./iproute2-4.10.0/ip/ip graft help
Usage: ip graft add NAME
          type { ipv4 | ipv6 } addr ADDR port PORT
          type unix path PATH
          [ netns { PID | NETNSNAME } ]

       ip graft del NAME

       ip graft show

Where: NAME := STRING
       ADDR := { IPv4_ADDRESS | IPv6_ADDRESS }
       PORT := { 0..65535 | dynamic }
       PATH := STRING
$ ./iproute2-4.10.0/ip/ip graft add ep-test type ipv4 addr 127.0.0.1 port 8080
$ ./iproute2-4.10.0/ip/ip graft show
ep-test type ipv4 addr 127.0.0.1 port 8080
```

This example creates a graft endpoint associated with 127.0.0.1:8080.
The AF_GRAFT socket assigned to ep-http is grafted onto the AF_INET
socket assigned to 127.0.0.1:8080. Note that if netns is not
specified, default netns is used for target endpoints.




### How to bind() AF_GRAFT sockets.

To bind AF_GRAFT sockets to graft endpoints, we introduced a new
sockaddr structure, struct sockaddr_gr. It is defined in
include/graft.h.

```c
struct sockaddr_gr {
        __kernel_sa_family_t    sgr_family;     /* AF_GRAFT */
        char sgr_epname[AF_GRAFT_EPNAME_MAX];   /* end point name */
};
```


Applications can create AF_GRAFT sockets and bind them to graft
endpoints following the familier socket API.

```c
int sock;
struct sockaddr_gr sgr;

sock = socket(AF_GRAFT, SOCK_STREAM, 0);

sgr.sgr_family = AF_GRAFT;
strncpy(sgr.sgr_epname, "ep-test", 7);

bind(sock, (struct sockaddr *)&sgr, sizeof(sgr));
```

Then, `sock` can be used as usual TCP sockets.



### Run Applications with AF_GRAFT

AF_GRAFT is a new address family; therefore, existing applications as
is cannot work with AF_GRAFT. A better solution is to support AF_GRAFT
in application codes; however, it requires various significant effort.

Therefore, we implemented a hijacking library to convert existing
applications to AF_GRAFT-capable. tools/libgraft-hijack.so overrides
socket-related functions and converts AF_INET or AF_INET6 sockets into
AF_GRAFT without modifications to their codes. This is achieved by the
[LD_PRELOAD
trick](https://yurichev.com/mirrors/LD_PRELOAD/lca2009.pdf).


```shell-session
$ LD_PRELOAD=/[PATH_TO_REPO_DIR]/tools/libgraft-hijack.so GRAFT_CONV_PAIRS="0.0.0.0:5201=ep-test" iperf3 -s
libgraft-hijack.so:466:socket(): overwrite family 10 with AF_GRAFT (4)
libgraft-hijack.so:597:setsockopt(): wrap setsockopt() level=1, optname=2
libgraft-hijack.so:531:bind(): no matched ep for fd=4, :::5201
warning: this system does not seem to support IPv6 - trying IPv4
libgraft-hijack.so:466:socket(): overwrite family 2 with AF_GRAFT (4)
libgraft-hijack.so:597:setsockopt(): wrap setsockopt() level=1, optname=2
libgraft-hijack.so:540:bind(): convert bind 0.0.0.0:5201 to ep-test
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------

```

This example runs iperf3 with an AF_GRAFT socket. `GRAFT_CONV_PAIRS`
specifies conversion mapping from original sockaddr to sockaddr_gr.
iperf3 try to bind 0.0.0.0:5201 (after :::5201). Then
libgraft-hijack.so overrides this bind() system call, and it calls
bind() with sockaddr_gr instead of sockaddr_in.



## Integration with Containers Platforms

ToDO

AF_GRAFT enables grafting sockets in containers onto sockets in host
network stack across the netns separation. However, we have not yet
implemented integration with container runtimes such as docker (under
development).

Instead, containers can directly configure graft endpoints in their
netns with the NET_ADMIN capabaility. The docker/ directory containes
two example Dockerfiles for testing AF_GRAFT with docker containers.

