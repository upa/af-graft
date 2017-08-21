/* libgrwrap.c */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <graft.h>

#define PROGNAME "libgrwrap.so"
#include "../test/util.h"

#include "list.h"


#define GRAFT_CONV_PAIRS_ENV	"GRAFT_CONV_PAIRS"


static int (*original_socket)(int domain, int type, int protocol);
static int (*original_bind)(int sockfd, const struct sockaddr *addr,
			    socklen_t addrlen);
static int (*original_setsockopt)(int fd, int level, int optname,
				  const void *optval, socklen_t optlen);

/* Lib Graft Wrapper:
 *
 * This library hijacks socket and bind syscalls to convert normal
 * sockets into AF_GRAFT-based sockets. This conversion is useful
 * for using existing applications with AF_GRAFT.
 *
 * - 1. hijack socket() with AF_INET or AF_INET6. 
 *
 * After hijacking, socket is created with AF_GRAFT, original 'type'
 * and 'protocol'.  Moreover, setsockopt GRAFT_SO_DELAYED and
 * GRAFT_SO_TRANSPARENT are set.
 *
 * 
 * - 2. hijack bind() with original sockaddr structure.
 *
 * After hijacking, bind() is called with struct sockaddr_gr with a
 * specified end point name.  Then, an actual socket on the specified
 * netns is created and delayed setsockopt()s are executed. Conversion
 * pairs from AF_INET/INET6 addresses into AF_GRAFT end points must be
 * stored in the GRAFT_CONV_PAIRS env valirable. The GRAFT_CONV_PAIRS
 * format is "ADDR1=EPNAME1 ADDR2=EPNAME2 ADDR3=EPNAME2 ...".
 */


#define MAX_CONVERTED_FDS 16
static int __converted_fds[MAX_CONVERTED_FDS] = {};


/* describing AF_INET/6 into AF_GRAFT address conversion pair */
struct addrconv {
	struct list_head list;

	char *pair;
	int family;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} addr;
	char *epname;
};

int parse_addrconv(char *var, struct list_head *list)
{
	/* parse GRAFT_CONV_PAIRS in *vars, add struct addrconv to
	 * *list, and returns the number of parsed pairs */
	int cnt = 0;
	char *p, *a;
	struct addrconv *ac, *tmp;

	for (p = strtok(var, " "); p != NULL; p = strtok(NULL, " ")) {
		if (p) {
			ac = (struct addrconv *)malloc(sizeof(*ac));
			memset(ac, 0, sizeof(*ac));
			ac->pair = p;
			list_add(&ac->list, list);
			cnt++;
		}
	}

	/* convert ac->air to addr and epname */
	list_for_each_entry_safe(ac, tmp, list, list) {
		for (a = ac->pair, p = ac->pair; p != '\0'; p++) {
			if (*p == '=') {
				/* delimiter of ADDR and EPNAME */
				*p = '\0';
				ac->epname = p + 1;
				break;
			}
		}

		if (inet_pton(AF_INET, a, &ac->addr) == 1)
			ac->family = AF_INET;
		else if (inet_pton(AF_INET6, a, &ac->addr) == 1)
			ac->family = AF_INET6;
		else {
			pr_e("invalid address %s", ac->pair);
			list_del(&ac->list);
			free(ac);
			ac = NULL;
			cnt--;
		}
	}

	return cnt;
}

void free_addrconv(struct list_head *list)
{
	struct addrconv *ac, *tmp;

	list_for_each_entry_safe(ac, tmp, list, list) {
		list_del(&ac->list);
		free(ac);
	}
}

int socket(int domain, int type, int protocol)
{
	int n, fd, ret, val;
	int new_domain = domain;

	original_socket = dlsym(RTLD_NEXT, "socket");

	if (domain == AF_INET || domain == AF_INET6) {
		pr_s("overwrite family %d with AF_GRAFT (%d)",
		     domain, AF_GRAFT);
		new_domain = AF_GRAFT;
	} else {
		return original_socket(domain, type, protocol);
	}

	fd = original_socket(new_domain, type, protocol);
	if (fd < 0)
		return fd;

	val = 1;
	ret = setsockopt(fd, IPPROTO_GRAFT,
			 GRAFT_SO_DELAYED, &val, sizeof(val));
	if (ret < 0) {
		pr_e("failed to set GRAFT_SO_DELAYED: %s", strerror(errno));
		return ret;
	}

	/* store the converted fd number */
	for (n = 0; n < MAX_CONVERTED_FDS; n++)
		if (__converted_fds[n] == 0)
			__converted_fds[n] = fd;

	return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int n, converted = 0;
	char *str_conv_pairs, buf[1024];
	struct list_head addrconv_list;
	struct addrconv *ac, *act;
	struct sockaddr_gr sgr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	original_bind = dlsym(RTLD_NEXT, "bind");

	/* check, is fd converted_fd ? */
	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (__converted_fds[n] == fd) {
			converted = 1;
			break;
		}
	}

	if (!converted)
		return original_bind(fd, addr, addrlen);

	/* ok, this is AF_GRAFT converted socket. */
	str_conv_pairs = getenv(GRAFT_CONV_PAIRS_ENV);
	if (!str_conv_pairs) {
		/* conversion rule is not specified */
		return original_bind(fd, addr, addrlen);		
	}
	
	strncpy(buf, str_conv_pairs, sizeof(buf));
	INIT_LIST_HEAD(&addrconv_list);
	parse_addrconv(buf, &addrconv_list);
	
	act = NULL;
	list_for_each_entry(ac, &addrconv_list, list) {
		if (ac->family != addr->sa_family)
			continue;

		switch (ac->family) {
		case AF_INET :
			sin = (struct sockaddr_in *)addr;
			if (memcmp(&ac->addr, &sin->sin_addr, 4) == 0)
				act = ac;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addr;
			if (memcmp(&ac->addr, &sin6->sin6_addr, 16) == 0)
				act = ac;
			break;
		default :
			pr_e("unsupported address family %d", ac->family);
			break;
		}

		if (act)
			break;
	}

	if (!act) {
		/* no matched pair */
		free_addrconv(&addrconv_list);
		return original_bind(fd, addr, addrlen);
	}

	free_addrconv(&addrconv_list);

	/* create sockaddr_gr and call bind with it */
	memset(&sgr, 0, sizeof(sgr));
	sgr.sgr_family = AF_GRAFT;
	strncpy(sgr.sgr_epname, act->epname, AF_GRAFT_EPNAME_MAX);

	pr_s("convert bind %s to %s", act->pair, act->epname);


	return original_bind(fd, (struct sockaddr *)&sgr, sizeof(sgr));
}

int setsockopt(int fd, int level, int optname,
	       const void *optval, socklen_t optlen)
{
	/* catch SOL_SOCKET setsockopts and wrap it into graft_sso_trans */

	char buf[GRAFT_SSO_TRANS_SIZE];
	struct graft_sso_trans *trans;

	original_setsockopt = dlsym(RTLD_NEXT, "setsockopt");

	if (level != SOL_SOCKET)
		return original_setsockopt(fd, level, optname, optval, optlen);

	/* wrap setsockopt params in graft_sso_trans */
	memset(buf, 0, sizeof(buf));
	trans = (struct graft_sso_trans *)buf;
	trans->level = level;
	trans->optname = optname;
	trans->optlen = optlen;
	memcpy(trans->optval, optval, optlen);

	return original_setsockopt(fd, IPPROTO_GRAFT, GRAFT_SO_TRANSPARENT,
				   trans, sizeof(buf));
}
