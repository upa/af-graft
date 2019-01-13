
AF_GRAFT
========

AF_GRAFT is a new socket address family for containers. AF_GRAFT
sockets can be _grafted_ onto other address family sockets _across
netns separation_.

By using AF_GRAFT, applications can utilize host network stacks
directly bypassing container network stacks. This mechanism improves
throughput and latency of containerized applications.

<img src="https://raw.githubusercontent.com/wiki/upa/af-graft/images/socket-grafting.png" width=450px>
Fig 1. The data path of AF_GRAFT: AF_GRAFT sockets in containers 
involve a single network stack bypassing conatiner network stack.

The detail is described in the paper [Grafting sockets for fast
container networking](https://dl.acm.org/citation.cfm?id=3230723) in
ACM/IEEE Symposium on Architectures for Networking and Communications
Systems 2018.


## Compile

We tested AF_GRAFT on
- Ubuntu 16.04, kernel 4.4.0-83-generic
- Ubuntu 18.04, kernel 4.15.0-43-generic
- Fedora 29, kernel 4.19.13-300

```shell-session
$ sudo apt install flex bison # for iproute2

$ git clone https://github.com/upa/af-graft.git
$ cd af-graft
$ make
```

In addition to the kernel module and tools, a modified iproute2 will
be compiled in accordance with your kernel version.

Note that the current implementation overwrites AF_IPX with AF_GRAFT
because Linux kernel prohibits dynamically adding a new address family
number.

```
$ sudo insmod af_graft.ko
insmod: ERROR: could not insert module af_graft.ko: File exists
```

So, the error above indicates that a socket protocol family is already
registered in the address family number, which is AF_IPX. In this
case, please rmmod the ipx kernel module.



## Install

```shell-session
$ cd af_graft
$ sudo make install
$ modprobe af_graft
```

default ip command is installed in /bin, and the AF_GRAFT-capable one
is installed in /sbin/ip. So, we recommend you to make an alias
ip=/sbin/ip.


## Endpoint

AF_GRAFT uses _Endpoints_ to specify which AF_GRAFT sockets to be
grafted onto which sockets. Endpoints are the same as the _names_ of
the bind() semantics: IP addresses and ports for AF_INET and AF_INET6
sockets, and file system paths for AF_UNIX. As well as such AFs,
AF_GRAFT has its endpoints (graft endpoints). Each graft endpoint,
which is identified by an arbitrary string, is associated with other
AF endpoints.

The modified iproute2 contained in this repository can configure graft
endpoints.

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
$ sudo /sbin/ip graft add ep-test type ipv4 addr 127.0.0.1 port 8080
$ /sbin/ip graft show
ep-test type ipv4 addr 127.0.0.1 port 8080
```

This example creates a graft endpoint associated with 127.0.0.1:8080.
The AF_GRAFT socket assigned to ep-http is grafted onto the AF_INET
socket assigned to 127.0.0.1:8080.

A graft endpoints and the associated actual endpoint can be placed on
different network namespaces. For example, making a graft endpoint at
a container and configuring the actual endpoint on a host network
stack provides network performance improvement by container network
stack bypassing.




## How to bind() AF_GRAFT sockets.

To bind AF_GRAFT sockets to graft endpoints, we introduced a new
sockaddr structure, `struct sockaddr_gr`. It is defined in
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



## Run Applications with AF_GRAFT

AF_GRAFT is a new address family, therefore, existing applications as
is cannot work with AF_GRAFT. A better solution is to support AF_GRAFT
in application codes; however, it requires various significant effort.

Therefore, we implemented a hijacking library to convert existing
applications to AF_GRAFT-capable. tools/libgraft-convert.so overrides
socket-related functions and converts AF_INET or AF_INET6 sockets into
AF_GRAFT without modifications to their codes. This relies on the
[LD_PRELOAD
trick](https://yurichev.com/mirrors/LD_PRELOAD/lca2009.pdf).


`tools/graft` command is a wrapper script to run applications with
AF_GRAFT by the LD_PRELOAD. libgraft-convert.so and the `graft`
command are installed into /usr/local/lib and /usr/local/bin
respectively by make install.


```shell-session
$ graft -h
/usr/local/bin/graft, AF_GRAFT conversion wrapper

Usage: /usr/local/bin/graft [-i INGRESS] [-e EGRESS] -- command arguments

optional arguments:
  -h    help
  -v    verbose mode
  -i ADDRESS:PORT=EPNAME, conversion for ingress connections
      PORT can be specified as range like PORT_START-PORT_END
  -e PREFIX:PREFLEN=EPNAME, conversion for egress connections
```



### Server-side sockets

There are two types of sockets, ingress and egress sockets (as known
as server-side and client-side sockets). An ingress socket is assigned
to an endpoint by bind(), and the application calls listen() and
accept() on the socket. At this side, `graft` command converts socket
address family and sockaddr structure for bind() into AF_GRAFT and
specified sockaddr_gr.

An example shown below converts 0.0.0.0:5201 for a socket of
iperf3 server into `ep-test` graft endpoint.

```shell-session
$ graft -i 0.0.0.0:5201=ep-test -- iperf3 -s -4
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------

```

The iperf3 server thinks it is listening on 0.0.0.0:5201, but it is
actually listening on ep-test, 127.0.0.1:8080. iperf3 clients can
connect to the server like:

```shell-session
$ iperf3 -c 127.0.0.1 -p 8080
Connecting to host 127.0.0.1, port 8080
[  4] local 127.0.0.1 port 38438 connected to 127.0.0.1 port 8080
```



### Client-side sockets

On the other hand, for the egress side, which means client sockets for
outbound connections, `-e` option can be used. This option specifies
source graft endpoints in accordance with the destination IP addresses
of the outbound connections.

```shell-session
$ sudo /sbin/ip graft add ep-out type ipv4 addr 127.0.0.1 port dynamic
$ /sbin/ip graft show
ep-out type ipv4 addr 127.0.0.1 port dynamic 
ep-test type ipv4 addr 127.0.0.1 port 8080

$ graft -e 0.0.0.0/0=ep-out -- iperf3 -c 127.0.0.1 -p 8080
Connecting to host 127.0.0.1, port 8080
[  4] local 127.0.0.1 port 57177 connected to 127.0.0.1 port 8080
```

The above example shows an iperf3 client with AF_GRAFT. All outbound
connections (destination 0.0.0.0/0) uses `ep-out` for their source
endpoints. Note that `port dynamic` indicates that sockets bind()ed
to this endpoint uses randomly selected port numbers as usual client
sockets.



### Note

1. `-i` option can specify port nubers in a range fashion like:

```shell-session
$ graft -i 0.0.0.0:0-65535=ep-test -- iperf3 -s -4
-----------------------------------------------------------
Server listening on 5201
-----------------------------------------------------------
```


2. `graft` command supports both IPv4 and IPv6, and multiple ingress
and egress conversion mappings. A use case is shown in [simple
integration with
docker](https://github.com/upa/af-graft/tree/master/docker), and a
simple example is: `graft -e 127.0.0.0/8=lo-out4 -e 0.0.0.0/0=ep-out4
-e 0::0/0=ep-out6 -i 127.0.0.1:0-65535=lo-in4 -i
0.0.0.0:0-65535=ep-in4`. The egress mapping follows the longest prefix
match basis, and the ingress mapping also allows multiple
mappings. This feature might be useful when the host network stack has
multiple interfaces.



3. `-v` option shows verbose message like:

```shell-session
$ graft -v -e 0.0.0.0/0=ep-out -- iperf3 -c 127.0.0.1 -p 8080
LD_PRELOAD=/usr/local/lib/libgraft-convert.so
GRAFT_VERBOSE=1
GRAFT_INGRESS_CONVERT=
GRAFT_EGRESS_CONVERT=0.0.0.0/0=ep-out
libgraft-convert.so:419:make_conv_prefix(): use ep ep-out for 0.0.0.0/0 (egress)
libgraft-convert.so:597:socket(): overwrite family 2 with AF_GRAFT
libgraft-convert.so:746:bind_before_connect(): use ep-out for 127.0.0.1:8080
Connecting to host 127.0.0.1, port 8080
libgraft-convert.so:597:socket(): overwrite family 2 with AF_GRAFT
libgraft-convert.so:746:bind_before_connect(): use ep-out for 127.0.0.1:8080
[  4] local 127.0.0.1 port 50583 connected to 127.0.0.1 port 8080
[ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
[  4]   0.00-1.00   sec  4.09 GBytes  35.1 Gbits/sec    0   3.12 MBytes       
[  4]   1.00-2.00   sec  3.95 GBytes  34.0 Gbits/sec    0   3.12 MBytes   
```



## Integration with Containers Platforms

ToDo

Integrating docker or kubernetes is difficult,, because docker network
plugin, CNI, and their abstractions focus on IP address and port
number management. Integrating new endpoint abstraction requires
significant effort..

Instead, we wrote a simple integration with docker containers. Please
see [here](https://github.com/upa/af-graft/tree/master/docker).
