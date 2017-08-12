/* graft.h */

#ifndef _GRAFT_H_
#define _GRAFT_H_

#include <linux/socket.h>	/* __kernel_sa_family_t */
#include <linux/if.h>		/* IFNAMSIZ */

#define GRAFT_VERSION "0.0.1"


#define AF_GRAFT	AF_IPX	/* overwrite IPX for GRAFT */
#define PF_GRAFT	AF_GRAFT


/* User API */

/* Structure describing an graft socket address (end point) */
#define AF_GRAFT_EPNAME_MAX	IFNAMSIZ

struct sockaddr_gr {
	__kernel_sa_family_t	sgr_family;	/* AF_GRAFT */
	char sgr_epname[AF_GRAFT_EPNAME_MAX];	/* end point name */
};


/* Graft socket options */

#define IPPROTO_GRAFT	254 /* Protocol level for setsockopt(2) */

/* When setsockopt() is called with IPPRPTO_GRAFT in 'level', graft
 * socket layer handles the setsockopt() manipulation unlike UNIX
 * domain socket (it is SOL_SOCKET level). setsockopt() with other
 * level such as IPPROTO_TCP or IPPROTO_RAW passes to host socket
 * setsockopt hadnlers. With SOL_SOCKET, it manipulates common socket
 * layer options as usual.
 */


#define GRAFT_SO_DELAYED		1
#define GRAFT_SO_DELAYED_EXECUTE	2
#define GRAFT_SO_DELAYED_RESULT		3
/*
 * - GRAFT_SO_DELAYED: optval is int, default is 0 (off)
 *
 * After GRAFT_SO_DELAYED option is set on, setsockopt() to host
 * sockets (not IPPROTO_GRAFT setsockopt()s) are queued and delayed
 * until bind() is called or GRAFT_SO_DELAYED_EXECUTE is set on. In
 * graft sockets, host sockets are not created until bind() is called
 * and the graft end point is decided. With this option, applications
 * can call setsockopt() to host sockets between a socket is created
 * and bind() is called. An obvious example is SO_REUSEADDR, which is
 * usually called after socket() before bind().
 *
 *
 * - GRAFT_SO_DELAYED_EXECUTE: no optval (NULL)
 *
 * This option is write-only. When GRAFT_SO_DELAYED_EXECUTE option is
 * set on with a non-negative value, queued setsockopt()s with
 * GRAFT_SO_DELAYED is executed even before bind(). setsockopt() with
 * GRAFT_SO_DELAYED_EXECUTE always returns 0 (success). To check the
 * return values of delayed setsockopt()s, check
 * GRAFT_SO_DELAYED_RESULT.
 *
 *
 * - GRAFT_SO_DELAYED_RESULT: optval is struct graft_sso_result
 *
 * This option is read-only. When an appcalition calls getsockopt()
 * with GRAFT_SO_DELAYED_RESULT, it resutrns all delayed setsockopt()
 * results to the applications. Results returned to user applications
 * disapper from kernel. After getsockopt() is called, an array of
 * struct graft_sso_result as many as delayed() setsockopt() is copied
 * to *optval, and optlen indicates the size of the array in byte.
 */

struct graft_sso_result {
	int level;
	int optname;
	int ret;
};



/* Generic Netlink AF_GRAFT definition */

#define AF_GRAFT_GENL_NAME	"af_graft"
#define AF_GRAFT_GENL_VERSION	0x00

/* genl commands */
enum {
	AF_GRAFT_CMD_ADD_ENDPOINT,
	AF_GRAFT_CMD_DEL_ENDPOINT,
	AF_GRAFT_CMD_GET_ENDPOINT,

	__AF_GRAFT_CMD_MAX,
};
#define AF_GRAFT_CMD_MAX	(__AF_GRAFT_CMD_MAX - 1)


/* genl attrs */

struct graft_genl_endpoint {
	char	epname[AF_GRAFT_EPNAME_MAX];	/* end point name */
	ssize_t			addrlen;	/* length of actual saddr */
	struct sockaddr_storage saddr;		/* host bind() end point */
};

enum {
	AF_GRAFT_ATTR_NONE,
	AF_GRAFT_ATTR_ENDPOINT,	/* struct graft_genl_endpoint */

	__AF_GRAFT_ATTR_MAX,
};
#define AF_GRAFT_ATTR_MAX	(__AF_GRAFT_ATTR_MAX - 1)


#endif
