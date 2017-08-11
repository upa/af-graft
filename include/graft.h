/* graft.h */

#ifndef _GRAFT_H_
#define _GRAFT_H_

#include <linux/socket.h>	/* __kernel_sa_family_t */
#include <linux/if.h>		/* IFNAMSIZ */

#define GRAFT_VERSION "0.0.1"


#define AF_GRAFT	AF_IPX	/* overwrite IPX for GRAFT */
#define PF_GRAFT	AF_GRAFT


/* User API through bind() */

#define AF_GRAFT_EPNAME_MAX	IFNAMSIZ

struct sockaddr_gr {
	__kernel_sa_family_t	sgr_family;	/* AF_GRAFT */
	char sgr_epname[AF_GRAFT_EPNAME_MAX];	/* end point name */
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

struct af_graft_endpoint {
	char sgr_epname[AF_GRAFT_EPNAME_MAX];	/* end point name */
	struct sockaddr_storage sgr_saddr;	/* host bind() end point */
};

enum {
	AF_GRAFT_ATTR_NONE,
	AF_GRAFT_ATTR_ENDPOINT,	/* struct afgraft_endpoint */

	__AF_GRAFT_ATTR_MAX,
};
#define AF_GRAFT_ATTR_MAX	(__AF_GRAFT_ATTR_MAX - 1)


#endif
