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
 * format is "ADDR1:PORT=EPNAME1 ADDR2:PORT=EPNAME2 ...". PORT 0 means
 * arbitrary port numbers.
 *
 * - 3. hijack setsockopt() to wrap setsockopt in graft_sso_trans
 *
 * - 4. hijack connect(), sned{to|msg}() for bind() before connect()
 */



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


#define ENV_GRAFT_DISABLE		"GRAFT"
#define ENV_GRAFT_CONV_PAIRS		"GRAFT_CONV_PAIRS"
#define NEV_GRAFT_BIND_BEFORE_CONN	"GRAFT_BBCONN"

static int (*original_socket)(int domain, int type, int protocol);
static int (*original_bind)(int sockfd, const struct sockaddr *addr,
			    socklen_t addrlen);
static int (*original_setsockopt)(int fd, int level, int optname,
				  const void *optval, socklen_t optlen);
static int (*original_close)(int fd);
static int (*original_connect)(int fd, const struct sockaddr *addr,
			       socklen_t addrlen);
/*
static ssize_t (*original_sendto)(int fd, const void *buf, size_t len,
				  int flags, const struct sockaddr *dest_addr,
				  socklen_t addrlen);
static ssize_t (*original_sendmsg)(int fd, const struct msghdr *msg,
				   int flags);
*/

#define MAX_CONVERTED_FDS	64
static int __converted_fds[MAX_CONVERTED_FDS] = {};

static int check_graft_enabled(void)
{
	char *p = getenv(ENV_GRAFT_DISABLE);

	if (p && strncmp(p, "disable", 7) == 0)
		return 0;

	return 1;
}

static int store_converted_fd(int fd)
{
	int n;

	/* store the converted fd number */
	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (__converted_fds[n] == 0) {
			__converted_fds[n] = fd;
			return 0;
		}
	}

	pr_e("over %d converted socckets!", MAX_CONVERTED_FDS);
	return -1;
}

static int check_converted_fd(int fd)
{
	int n;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (__converted_fds[n] == fd) {
			return 1;
		}
	}

	return 0;
}

static void release_converted_fd(int fd)
{
	int n;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (__converted_fds[n] == fd) {
			__converted_fds[n] = 0;
		}
	}
}

/* describing AF_INET/6 into AF_GRAFT address conversion pair */
struct addrconv {
	struct list_head list;

	char *pair;
	int family;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} addr;
	uint16_t port;
	char *epname;
};

int parse_addrconv(char *var, struct list_head *list)
{
	/* parse GRAFT_CONV_PAIRS in *vars, add struct addrconv to
	 * *list, and returns the number of parsed pairs */
	int cnt = 0, n;
	char *p, *addr, *port;
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

	/* convert ac->pair to addr and epname */
	list_for_each_entry_safe(ac, tmp, list, list) {

		addr = ac->pair;

		for (p = ac->pair; p != '\0'; p++) {
			if (*p == '=') {
				/* delimiter of ADDR:PORT and EPNAME */
				*p = '\0';
				ac->epname = p + 1;
				break;
			}
		}

		for (n = strlen(ac->pair) - 1; n >= 0; n--) {
			p = ac->pair + n;
			if (*p == ':') {
				/* delimiter of ADDR and PORT */
				*p = '\0';
				port = p + 1;
				break;
			}
		}

		ac->port = htons(atoi(port));

		if (inet_pton(AF_INET, addr, &ac->addr) == 1)
			ac->family = AF_INET;
		else if (inet_pton(AF_INET6, addr, &ac->addr) == 1)
			ac->family = AF_INET6;
		else {
			pr_e("invalid address %s", ac->pair);
			list_del(&ac->list);
			free(ac);
			ac = NULL;
			cnt--;
			continue;
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
	int fd, ret, val;
	int new_domain = domain;

	original_socket = dlsym(RTLD_NEXT, "socket");

	if (!check_graft_enabled())
		return original_socket(domain, type, protocol);

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

	if (store_converted_fd(fd) < 0)
		return -ENOBUFS;

	return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	char *str_conv_pairs, buf[1024];
	struct list_head addrconv_list;
	struct addrconv *ac, *act;
	struct sockaddr_gr sgr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	original_bind = dlsym(RTLD_NEXT, "bind");

	if (!check_graft_enabled() || !check_converted_fd(fd))
		return original_bind(fd, addr, addrlen);

	/* ok, this is AF_GRAFT converted socket. */
	str_conv_pairs = getenv(ENV_GRAFT_CONV_PAIRS);
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
			if (memcmp(&ac->addr, &sin->sin_addr, 4) == 0 &&
			    (ac->port == 0 || ac->port == sin->sin_port))
				act = ac;
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)addr;
			if (memcmp(&ac->addr, &sin6->sin6_addr, 16) == 0 &&
			    (ac->port == 0 || ac->port == sin6->sin6_port))
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

	pr_s("convert bind %s:%u to %s",
	     act->pair, ntohs(ac->port), act->epname);


	return original_bind(fd, (struct sockaddr *)&sgr, sizeof(sgr));
}

int setsockopt(int fd, int level, int optname,
	       const void *optval, socklen_t optlen)
{
	/* catch SOL_SOCKET setsockopts and wrap it into graft_sso_trans */

	char buf[GRAFT_SSO_TRANS_SIZE];
	struct graft_sso_trans *trans;

	original_setsockopt = dlsym(RTLD_NEXT, "setsockopt");

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    level != SOL_SOCKET)
		return original_setsockopt(fd, level, optname, optval, optlen);

	/* wrap setsockopt params in graft_sso_trans */
	pr_s("wrap setsockopt() level=%d, optname=%d", level, optname);
	memset(buf, 0, sizeof(buf));
	trans = (struct graft_sso_trans *)buf;
	trans->level = level;
	trans->optname = optname;
	trans->optlen = optlen;
	memcpy(trans->optval, optval, optlen);

	return original_setsockopt(fd, IPPROTO_GRAFT, GRAFT_SO_TRANSPARENT,
				   trans, sizeof(buf));
}

int close(int fd)
{
	original_close = dlsym(RTLD_NEXT, "close");

	if (!check_graft_enabled() || !check_converted_fd(fd))
		return original_close(fd);

	release_converted_fd(fd);

	return original_close(fd);
}

static int bind_before_connect(int fd, char *epname)
{
	int ret;
	struct sockaddr_gr sgr;
	struct sockaddr_storage ss;
	socklen_t addrlen;

	/* check is fd already bind()ed */
	addrlen = sizeof(ss);

	ret = getsockname(fd, (struct sockaddr *)&ss, &addrlen);

	if (ret < 0) {
		pr_e("getsockname failed: %s", strerror(errno));
		return ret;
	}
	if (addrlen > 0)
		return 0;

	/* ok, this socket is not bind()ed, lets bind() */
	memset(&sgr, 0, sizeof(sgr));
	sgr.sgr_family = AF_GRAFT;
	strncpy(sgr.sgr_epname, epname, AF_GRAFT_EPNAME_MAX);


	return original_bind(fd, (struct sockaddr *)&sgr, sizeof(sgr));
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	/* call bind() before connect() using GRAFT_BBC */
	int ret;
	char *p;

	if (!check_graft_enabled() || !check_converted_fd(fd))
		return original_connect(fd, addr, addrlen);

	p = getenv(NEV_GRAFT_BIND_BEFORE_CONN);
	if (!p) {
		pr_e("%s is not defined", NEV_GRAFT_BIND_BEFORE_CONN);
		return -EINVAL;
	}

	pr_s("call bind() to %s before connect()", p);
	ret = bind_before_connect(fd, p);
	if (ret < 0)
		return ret;

	return original_connect(fd, addr, addrlen);
}

