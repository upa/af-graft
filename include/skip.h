/* skip.h */

#ifndef _SKIP_H_
#define _SKIP_H_

#include <linux/socket.h>	/* __kernel_sa_family_t */
#include <linux/if.h>		/* IFNAMSIZ */

#define SKIP_VERSION "0.0.1"


#define AF_SKIP	AF_IPX	/* overwrite IPX for SKIP */
#define PF_SKIP	AF_SKIP


/* User API through bind() */

#define AF_SKIP_EPNAME_MAX	IFNAMSIZ

struct sockaddr_skip {
	__kernel_sa_family_t	ssk_family;	/* AF_SKIP */
	char ssk_epname[AF_SKIP_EPNAME_MAX];	/* end point name */
};




/* Generic Netlink AF_SKIP definition */

#define AF_SKIP_GENL_NAME	"af_skip"
#define AF_SKIP_GENL_VERSION	0x00

/* genl commands */
enum {
	AF_SKIP_CMD_ADD_ENDPOINT,
	AF_SKIP_CMD_DEL_ENDPOINT,
	AF_SKIP_CMD_GET_ENDPOINT,

	__AF_SKIP_CMD_MAX,
};
#define AF_SKIP_CMD_MAX	(__AF_SKIP_CMD_MAX - 1)


/* genl attrs */

struct af_skip_endpoint {
	char ssk_epname[AF_SKIP_EPNAME_MAX];	/* end point name */
	struct sockaddr_storage ssk_saddr;	/* host bind() end point */
};

enum {
	AF_SKIP_ATTR_NONE,
	AF_SKIP_ATTR_ENDPOINT,	/* struct afskip_endpoint */

	__AF_SKIP_ATTR_MAX,
};
#define AF_SKIP_ATTR_MAX	(__AF_SKIP_ATTR_MAX - 1)


#endif
