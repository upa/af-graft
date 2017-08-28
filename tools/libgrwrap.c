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
#include <stdbool.h>
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


#define ENV_GRAFT_DISABLED		"GRAFT"
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
static ssize_t (*original_sendto)(int fd, const void *buf, size_t len,
				  int flags, const struct sockaddr *dest,
				  socklen_t addrlen);
static ssize_t (*original_sendmsg)(int fd, const struct msghdr *msg,
				   int flags);

static bool graft_disabled = false;
#define check_graft_enabled()	(!graft_disabled)
#define set_graft_disabled()	do { graft_disabled = true; } while (0)



/* Converted File Descriptors */
#define MAX_CONVERTED_FDS	64
struct converted_fd {
	int fd;
	bool bound;	/* bind() is called or not */
};
static struct converted_fd converted_fds[MAX_CONVERTED_FDS] = {{}};



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
static struct list_head addrconv_list;	/* parsed aaddrconv list */

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





/* Entry Point and Exit Point of LibGrWrapped Application */
void libgrwrap_cleanup(void)
{
	free_addrconv(&addrconv_list);
}

__attribute__((constructor))
void libgrwrap_hijack(void)
{
	char buf[1024];
	char *str_conv_pairs;

	/* hijacking syscalls */
	original_socket = dlsym(RTLD_NEXT, "socket");
	original_bind = dlsym(RTLD_NEXT, "bind");
	original_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
	original_close = dlsym(RTLD_NEXT, "close");
	original_bind = dlsym(RTLD_NEXT, "bind");
	original_connect = dlsym(RTLD_NEXT, "connect");

	/* check GRAFT disable or not */
	if (getenv(ENV_GRAFT_DISABLED) &&
	    strncmp(getenv(ENV_GRAFT_DISABLED), "disable", 7) == 0)
		set_graft_disabled();

	/* parse address conversion pairs */
	INIT_LIST_HEAD(&addrconv_list);
	str_conv_pairs = getenv(ENV_GRAFT_CONV_PAIRS);
	if (str_conv_pairs) {
		strncpy(buf, str_conv_pairs, sizeof(buf));
		parse_addrconv(buf, &addrconv_list);
	}

	/* register cleanup handler */
	atexit(libgrwrap_cleanup);
}



/* Managing converted socket file descriptors */
static int store_converted_fd(int fd)
{
	int n;

	/* store the converted fd number */
	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (converted_fds[n].fd == 0) {
			converted_fds[n].fd = fd;
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
		if (converted_fds[n].fd == fd) {
			return 1;
		}
	}

	return 0;
}

static void release_converted_fd(int fd)
{
	int n;
	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (converted_fds[n].fd == fd) {
			converted_fds[n].fd = 0;
			converted_fds[n].bound = false;
			return;
		}
	}
}

static void set_bound_converted_fd(int fd)
{
	int n;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (converted_fds[n].fd == fd) {
			converted_fds[n].bound = true;
			return;
		}
	}
}

static bool check_bound_converted_fd(int fd)
{
	int n;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (converted_fds[n].fd == fd) {
			return converted_fds[n].bound;
		}
	}

	return false;
}




/* Hijacked syscalls */
int socket(int domain, int type, int protocol)
{
	int fd, ret, val;
	int new_domain = domain;

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

	/* setsockopt SO_DELAYED until host socket is created */
	val = 1;
	ret = original_setsockopt(fd, IPPROTO_GRAFT, GRAFT_SO_DELAYED,
				  &val, sizeof(val));
	if (ret < 0) {
		pr_e("failed to set GRAFT_SO_DELAYED: %s", strerror(errno));
		return ret;
	}

	/* setsockopt NAME_TRANSPARENT forever */
	val = 1;
	ret = original_setsockopt(fd, IPPROTO_GRAFT, GRAFT_NAME_TRANSPARENT,
				  &val, sizeof(val));
	if (ret < 0) {
		pr_e("failed to set GRAFT_NAME_TRANSPARENT: %s",
		     strerror(errno));
		return ret;
	}

	if (store_converted_fd(fd) < 0) {
		close(fd);
		return -ENOBUFS;
	}

	return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret, val;
	struct addrconv *ac, *act;
	struct sockaddr_gr sgr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    addr->sa_family == AF_GRAFT)
		return original_bind(fd, addr, addrlen);

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

	/* no matched conversion pair */
	if (!act)
		return original_bind(fd, addr, addrlen);

	/* create sockaddr_gr and call bind() with it */
	memset(&sgr, 0, sizeof(sgr));
	sgr.sgr_family = AF_GRAFT;
	strncpy(sgr.sgr_epname, act->epname, AF_GRAFT_EPNAME_MAX);

	pr_s("convert bind %s:%u to %s",
	     act->pair, ntohs(ac->port), act->epname);

	ret = original_bind(fd, (struct sockaddr *)&sgr, sizeof(sgr));
	if (ret == 0) {
		/* bind() success. host socket is created.
		 * Thus, SO_DELAYED is no longer needed */
		set_bound_converted_fd(fd);
		val = 0;
		if (original_setsockopt(fd, IPPROTO_GRAFT, GRAFT_SO_DELAYED,
					&val, sizeof(val)) < 0)
			pr_e("failed to disable GRAFT_SO_DELAYED for %d", fd);
	}

	return ret;
}

static int bind_before_connect(int fd)
{
	int ret, val;
	char *epname;
	struct sockaddr_gr sgr;

	/* check is fd already bind()ed */
	if (check_bound_converted_fd(fd))
		return 0;

	epname = getenv(NEV_GRAFT_BIND_BEFORE_CONN);
	if (!epname) {
		pr_e("%s is not defined", NEV_GRAFT_BIND_BEFORE_CONN);
		return -EINVAL;
	}

	/* ok, this socket is not bind()ed, lets bind() */
	memset(&sgr, 0, sizeof(sgr));
	sgr.sgr_family = AF_GRAFT;
	strncpy(sgr.sgr_epname, epname, AF_GRAFT_EPNAME_MAX);

	ret = original_bind(fd, (struct sockaddr *)&sgr, sizeof(sgr));
	if (ret == 0) {
		/* bind() success. host socket is created.
		 * Thus, SO_DELAYED is no longer needed */
		set_bound_converted_fd(fd);
		val = 0;
		if (original_setsockopt(fd, IPPROTO_GRAFT, GRAFT_SO_DELAYED,
					&val, sizeof(val)) < 0)
			pr_e("failed to disable GRAFT_SO_DELAYED for %d", fd);
	}

	return ret;
}

int setsockopt(int fd, int level, int optname,
	       const void *optval, socklen_t optlen)
{
	/* catch SOL_SOCKET setsockopt and wrap it into graft_sso_trans */

	char buf[GRAFT_SSO_TRANS_SIZE];
	struct graft_sso_trans *trans;

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
	if (!check_graft_enabled() || !check_converted_fd(fd))
		return original_close(fd);

	release_converted_fd(fd);

	return original_close(fd);
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	/* call bind() before connect() using GRAFT_BBCONN */
	int ret;

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    check_bound_converted_fd(fd))
		return original_connect(fd, addr, addrlen);

	pr_s("call bind() before connect()");
	ret = bind_before_connect(fd);
	if (ret < 0) {
		pr_e("bind() before connect() failed: %s", strerror(errno));
		return ret;
	}

	return original_connect(fd, addr, addrlen);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, 
	       const struct sockaddr *dest, socklen_t addrlen)
{
	int ret;

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    check_bound_converted_fd(fd))
		return original_sendto(fd, buf, len, flags, dest, addrlen);

	pr_s("call bind() before connect()");
	ret = bind_before_connect(fd);
	if (ret < 0) {
		pr_e("bind() before connect() failed: %s", strerror(errno));
		return ret;
	}

	return original_sendto(fd, buf, len, flags, dest, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	int ret;

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    check_bound_converted_fd(fd))
		return original_sendmsg(fd, msg, flags);

	pr_s("call bind() before connect()");
	ret = bind_before_connect(fd);
	if (ret < 0) {
		pr_e("bind() before connect() failed: %s", strerror(errno));
		return ret;
	}

	return original_sendmsg(fd, msg, flags);
}

