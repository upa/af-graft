/*
 * libgraft.c
 *
 * - GRAFT_INGRESS_CONVERT
 * param is "ADDR:PORT=EPNAME ADDR:PORT=EPNAME ..."
 * PORT can be specified as range like PORT_START-PORT_END
 *
 * - GRAFT_EGRESS_CONVERT
 * param is "PREFIX/LEN=EPNAME PREFIX/LEN=EPNAME ..."
 *
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
#include <netdb.h>
#include <linux/genetlink.h>

#include <graft.h>
#include "patricia.h"
#include "list.h"


#define PROGNAME "libgraft-convert.so"
#include "../test/util.h"

/* print if verbose */
static int verbose_level = 0;
#define verbose_level_inc() verbose_level++
#define pr_v(fmt, ...) if (verbose_level) { pr(fmt, __VA_ARGS__); }
#define pr_vs(fmt, ...) if (verbose_level) { pr_s(fmt, __VA_ARGS__); }

#define ENV_GRAFT_VERBOSE	"GRAFT_VERBOSE"
#define ENV_GRAFT_INGRESS	"GRAFT_INGRESS_CONVERT"
#define ENV_GRAFT_EGRESS	"GRAFT_EGRESS_CONVERT"


struct conv_fd {
	int fd;		/* the fd converted for AF_GRAFT */
	bool bind;	/* bind() is called or not */
};
#define MAX_CONVERTED_FDS	64


struct conv_addr {
	struct list_head list;			/* libgraft.ingress_list*/

	int family;				/* original address family */
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} addr;					/* original address for bind */
	int port_start, port_end;		/* port number range */
	char epname[AF_GRAFT_EPNAME_MAX];	/* target graft endpoint */
};

struct conv_prefix {
	prefix_t prefix;			/* destination prefix */
	char epname[AF_GRAFT_EPNAME_MAX];	/* target graft endpoint */
};

/* describing libgraft */
struct libgraft {
	struct conv_fd		cfds[MAX_CONVERTED_FDS]; /* converted fds */
	struct list_head	ingress_list;	/* list for ingress bind() */
	patricia_tree_t		*egress_tree4;	/* tree for egress bind() */
	patricia_tree_t		*egress_tree6;	/* tree for egress bind() */
};
static struct libgraft libgraft;


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



/* converted fd management */
static int store_converted_fd(int fd)
{
	int n;
	struct conv_fd *cfds = libgraft.cfds;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (cfds[n].fd == 0) {
			cfds[n].fd = fd;
			return 0;
		}
	}

	pr_e("over %d converted fds", MAX_CONVERTED_FDS);
	return -1;
}

static bool is_converted_fd(int fd)
{
	int n;
	struct conv_fd *cfds = libgraft.cfds;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (cfds[n].fd == fd)
			return true;
	}

	return false;
}

static void release_converted_fd(int fd)
{
	int n;
	struct conv_fd *cfds = libgraft.cfds;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (cfds[n].fd == fd) {
			cfds[n].fd = 0;
			cfds[n].bind = false;
			return;
		}
	}
}

static void set_bind_converted_fd(int fd)
{
	int n;
	struct conv_fd *cfds = libgraft.cfds;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (cfds[n].fd == fd) {
			cfds[n].bind = true;
			return;
		}
	}
}


static bool is_bind_converted_fd(int fd)
{
	int n;
	struct conv_fd *cfds = libgraft.cfds;

	for (n = 0; n < MAX_CONVERTED_FDS; n++) {
		if (cfds[n].fd == fd) {
			return cfds[n].bind;
		}
	}
	/* not reached */
	pr_e("no matched converted fd for %d",fd);
	return false;
}


/* XXX: should handle return value */
static void sockaddr_ntop(const struct sockaddr *sa, char *dst, int len)
{
	char portbuf[64];

	switch (sa->sa_family) {
	case AF_INET :
		inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr,
			  dst, len);
		snprintf(portbuf, sizeof(portbuf), ":%u",
			 ntohs(((struct sockaddr_in *)sa)->sin_port));
		strncat(dst, portbuf, len);
		break;

	case AF_INET6 :
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr,
			      dst, len);
		snprintf(portbuf, sizeof(portbuf), ":%u",
			 ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
		strncat(dst, portbuf, len);
		break;
	case AF_GRAFT :
		snprintf(dst, len, "graft:%s",
			 ((struct sockaddr_gr *)sa)->sgr_epname);
		break;
	default :
		snprintf(dst, len, "unknown family %d", sa->sa_family);
	}
}



/* parse environmental varibales */

static struct conv_addr *make_conv_addr(char *node, char *serv, char *epname)
{
	char *p, *start, *end;
	struct conv_addr *ca;
	
	ca = (struct conv_addr *)malloc(sizeof(struct conv_addr));
	if (!ca) {
		pr_e("no buffer available: %s", strerror(errno));
		return NULL;
	}

	/* convert address from string to binary */
	if (inet_pton(AF_INET, node, &ca->addr) == 1)
		ca->family = AF_INET;
	else if (inet_pton(AF_INET6, node, &ca->addr) == 1)
		ca->family = AF_INET6;
	else {
		pr_e("invalid address %s", node);
		goto err_out;
	}

	/* obtain port number */
	start = serv;
	end = serv;
	if ((p = strchr(serv, '-'))) {
		/* this is range */
		end = p + 1;
		*p = '\0';
	}

	ca->port_start = atoi(start);
	ca->port_end = atoi(end);
	if (ca->port_start < 0 || ca->port_start > 0xFFFF ||
	    ca->port_end < 0 || ca->port_end > 0xFFFF) {
		pr_e("invalid port range %d-%d", ca->port_start, ca->port_end);
		goto err_out;
	}
		

	strncpy(ca->epname, epname, AF_GRAFT_EPNAME_MAX);

	pr_v("use %s for %s:%d-%d (ingress)", epname, node,
	     ca->port_start, ca->port_end);

	return ca;

err_out:
	free(ca);
	return NULL;
}

static int parse_graft_ingress(char *var)
{
	/* parse GRAFT_INGRESS_CONVERT.
	 * param is "ADDR:PORT=EPNAME ..."
	 * each pair is converted into struct conv_addr and stored to 
	 * libgraft.ingres_list. PORT can be specified as range
	 * like PORT_START-PORT_END
	 */

	int n, i;
	char *p, *tok, *node, *serv, *epname;
	struct conv_addr *ca;

	n = 0;
	for (tok = strtok(var, " "); tok != NULL; tok = strtok(NULL, " ")) {
		if (!tok)
			continue;

		node = NULL;
		serv = NULL;
		epname = NULL;

		/* split ADDR:PORT and EPNAME by '=' */
		for (p = tok; *p != '\0'; p++) {
			if (*p == '=') {
				*p = '\0';
				node = tok;
				epname = p + 1;
				break;
			}
		}
		if (!node || !epname)
			goto err_out;

		/* split ADDR and port by ':' */
		for (i = strlen(node); i >= 0; i--) {
			p = tok + i;
			if (*p == ':') {
				*p = '\0';
				serv = p + 1;
				break;
			}
		}
		if (!serv)
			goto err_out;

		ca = make_conv_addr(node, serv, epname);
		if (!ca)
			goto err_out;

		list_add_tail(&ca->list, &libgraft.ingress_list);
		n++;
	}
	
	return n;

err_out:
	pr_e("invalid ingress pair %s:%s=%s", node, serv, epname);
	return -EINVAL;
}
	

static int compare_conv_addr(const struct sockaddr *sa, struct conv_addr *ca)
{
	int n, port, alen, ret;
	void *addr;

	if (sa->sa_family != ca->family)
		return -1;

	/* compare address */
	switch (sa->sa_family) {
	case AF_INET:
		alen = sizeof(struct in_addr);
		addr = &(((struct sockaddr_in*)sa)->sin_addr);
		port = ((struct sockaddr_in*)sa)->sin_port;
		break;
	case AF_INET6:
		alen = sizeof(struct in6_addr);
		addr = &(((struct sockaddr_in6*)sa)->sin6_addr);
		port = ((struct sockaddr_in6*)sa)->sin6_port;
		break;
	default:
		pr_e("unsupported address family %d", sa->sa_family);
		return -1;
	}

	ret = memcmp(addr, &ca->addr, alen);
	if (ret != 0)
		return ret;

	/* check port range */
	for (n = ca->port_start; n <= ca->port_end; n++) {
		if (port == htons(n))
			return 0;
	}

	return -1;
}

static struct conv_addr *find_conv_addr(const struct sockaddr *sa)
{
	struct conv_addr *ca;

	list_for_each_entry(ca, &libgraft.ingress_list, list) {
		if (compare_conv_addr(sa, ca) == 0)
			return ca;
	}

	return NULL;
}
	


static struct conv_prefix *make_conv_prefix(char *prefix, char *length,
					    char *epname)
{
	void *dest;
	int r, preflen;
	struct conv_prefix *cp;
	struct addrinfo hints, *res;

	cp = (struct conv_prefix *)malloc(sizeof(struct conv_prefix));
	if (!cp) {
		pr_e("no buffer available: %s", strerror(errno));
		return NULL;
	}

	preflen = atoi(length);

	/* validate the prefix */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	r = getaddrinfo(prefix, NULL, &hints, &res);
	if (r != 0 || !res) {
		pr_e("invalid address of prefix %s", prefix);
		goto err_out;
	}

	if (res->ai_family == AF_INET)
		dest = &(((struct sockaddr_in*)(res->ai_addr))->sin_addr);
	else if (res->ai_family == AF_INET6)
		dest = &(((struct sockaddr_in6*)(res->ai_addr))->sin6_addr);
	else {
		pr_e("unsupported address family %d", res->ai_family);
		goto err_out;
	}

	if ((preflen < 0) ||
	    (res->ai_family == AF_INET && preflen > 32) ||
	    (res->ai_family == AF_INET6 && preflen > 128)) {
		pr_e("invalid prefix length %s for %s", length, prefix);
		goto err_out;
	}

	/* ok, make it prefix_t */
	New_Prefix2(res->ai_family, dest, preflen, &cp->prefix);
	strncpy(cp->epname, epname, AF_GRAFT_EPNAME_MAX);

	pr_v("use ep %s for %s/%s (egress)", epname, prefix, length);

	return cp;

err_out:
	free(cp);
	return NULL;
}

static int parse_graft_egress(char *var)
{
	/* parse GRAFT_EGRESS_CONVERT.
	 * param is "PREFIX/LEN=EPNAME ..."
	 * each pair is converted into struct conv_prefix and stored to 
	 * libgraft.egress_tree
	 */

	int n, i;
	char *p, *tok, *prefix, *length, *epname;
	struct conv_prefix *cp;
	patricia_node_t *p_node;

	n = 0;
	for (tok = strtok(var, " "); tok != NULL; tok = strtok(NULL, " ")) {
		if (!tok)
			continue;

		prefix = NULL;
		length = NULL;
		epname = NULL;

		/* split PREFIX/LEN and EPNAME by '=' */
		for (p = tok; *p != '\0'; p++) {
			if (*p == '=') {
				*p = '\0';
				prefix = tok;
				epname = p + 1;
				break;
			}
		}
		if (!prefix || !epname)
			goto err_out;

		/* split PREFIX and LEN by '/' */
		for (i = strlen(prefix); i >= 0; i--) {
			p = tok + i;
			if (*p == '/') {
				*p = '\0';
				length = p + 1;
				break;
			}
		}
		if (!length)
			goto err_out;

		cp = make_conv_prefix(prefix, length, epname);
		if (!cp)
			goto err_out;

		switch (cp->prefix.family) {
		case AF_INET:
			p_node = patricia_lookup(libgraft.egress_tree4,
						 &cp->prefix);
			break;
		case AF_INET6:
			p_node = patricia_lookup(libgraft.egress_tree6,
						 &cp->prefix);
			break;
		default:
			pr_e("invalid address family %u", cp->prefix.family);
			goto err_out;
		}

		if (p_node->data) {
			pr_e("prefix pair dup for %s/%s", prefix, length);
			goto err_out;
		}
		p_node->data = cp;
		
		n++;
	}
	
	return n;

err_out:
	pr_e("invalid egress pair %s/%s=%s", prefix, length, epname);
	return -EINVAL;
}


static struct conv_prefix *find_conv_prefix(const struct sockaddr *sa)
{
	prefix_t prefix;
	patricia_node_t *p_node;
	patricia_tree_t *tree;

	switch(sa->sa_family) {
	case AF_INET:
		New_Prefix2(sa->sa_family,
			    &(((struct sockaddr_in*)sa)->sin_addr),
			    32, &prefix);
		tree = libgraft.egress_tree4;
		break;
	case AF_INET6:
		New_Prefix2(sa->sa_family,
			    &(((struct sockaddr_in6*)sa)->sin6_addr),
			    128, &prefix);
		tree = libgraft.egress_tree6;
		break;
	default:
		pr_e("unsupported address family %u", sa->sa_family);
		return NULL;
	}
		
	p_node = patricia_search_best(tree, &prefix);
	if (!p_node || !p_node->data) {
		return NULL;
	}

	return p_node->data;
}


__attribute__((constructor))
void libgraft_hijack(void)
{
	int ret;
	char buf[2048];

	memset(&libgraft, 0, sizeof(libgraft));
	INIT_LIST_HEAD(&libgraft.ingress_list);
	libgraft.egress_tree4 = New_Patricia(32);
	libgraft.egress_tree6 = New_Patricia(128);

	/* hijacking syscalls */
	original_socket		= dlsym(RTLD_NEXT, "socket");
	original_bind		= dlsym(RTLD_NEXT, "bind");
	original_setsockopt	= dlsym(RTLD_NEXT, "setsockopt");
	original_close		= dlsym(RTLD_NEXT, "close");
	original_bind		= dlsym(RTLD_NEXT, "bind");
	original_connect	= dlsym(RTLD_NEXT, "connect");
	original_sendto		= dlsym(RTLD_NEXT, "sendto");
	original_sendmsg	= dlsym(RTLD_NEXT, "sendmsg");

	/* set verbose level */
	if (getenv(ENV_GRAFT_VERBOSE)) {
		verbose_level = atoi(getenv(ENV_GRAFT_VERBOSE));
	}

	/* parse ingress address conversion pairs */
	if (getenv(ENV_GRAFT_INGRESS)) {
		strncpy(buf, getenv(ENV_GRAFT_INGRESS), sizeof(buf));
		ret = parse_graft_ingress(buf);
		if (ret < 0)
			exit(ret);
	}

	/* parse egress prefix conversion pairsw */
	if (getenv(ENV_GRAFT_EGRESS)) {
		strncpy(buf, getenv(ENV_GRAFT_EGRESS), sizeof(buf));
		ret = parse_graft_egress(buf);
		if (ret < 0)
			exit(ret);
	}
}



/* hijacked syscalls */

int socket(int domain, int type, int protocol)
{
	int fd, ret, val;
	int new_domain = domain;

	switch (domain) {
	case AF_INET:
	case AF_INET6:
		pr_vs("overwrite family %d with AF_GRAFT", domain);
	case AF_GRAFT:
		new_domain = AF_GRAFT;
		break;
	default:
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

static int bind_for_graft_ep(int fd, char *epname)
{
	int ret, val;
	struct sockaddr_gr sgr;

	memset(&sgr, 0, sizeof(sgr));
	sgr.sgr_family = AF_GRAFT;
	strncpy(sgr.sgr_epname, epname, AF_GRAFT_EPNAME_MAX);

	ret = original_bind(fd, (struct sockaddr *)&sgr, sizeof(sgr));
	if (ret == 0) {
		/* bind() success. host socket is created.
		 * Thus, SO_DELAYED is no longer needed */
		set_bind_converted_fd(fd);
		val = 0;
		if (original_setsockopt(fd, IPPROTO_GRAFT, GRAFT_SO_DELAYED,
					&val, sizeof(val)) < 0)
			pr_e("failed to disable GRAFT_SO_DELAYED for %d", fd);
	}

	return ret;
}

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	char buf[64];
	socklen_t slen;
	struct conv_addr *ca;
	struct sockaddr_storage ss;

	if (!is_converted_fd(fd) || addr->sa_family == AF_GRAFT)
		return original_bind(fd, addr, addrlen);

	/* check this socket is already bind()ed */
	slen = sizeof(ss);
	memset(&ss, 0, sizeof(ss));
	if (getsockname(fd, (struct sockaddr *)&ss, &slen) == 0) {
		if (ss.ss_family != 0)
			return 0;
	}

	ca = find_conv_addr(addr);
	sockaddr_ntop(addr, buf, sizeof(buf));

	/* no matched conversion pair */
	if (!ca) {
		pr_e("no matched ep for fd=%d, %s. call original bind",
		     fd, buf);

		/* XXX: bind() for AF_GRAFT family socket with
		 * original sockaddr (in or in6) fails due to
		 * EAFNOSUPPORT. is this correct behavior? */
		return original_bind(fd, addr, addrlen);
	}

	pr_vs("convert bind %s to %s", buf, ca->epname);
	return bind_for_graft_ep(fd, ca->epname);
}


int setsockopt(int fd, int level, int optname,
	       const void *optval, socklen_t optlen)
{
	/* catch SOL_SOCKET setsockopt and wrap it into graft_sso_trans */

	char buf[GRAFT_SSO_TRANS_SIZE];
	struct graft_sso_trans *trans;

	if (!is_converted_fd(fd) || level != SOL_SOCKET)
		return original_setsockopt(fd, level, optname, optval, optlen);

	/* wrap setsockopt params in graft_sso_trans */
	pr_vs("wrap setsockopt() level=%d, optname=%d", level, optname);
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
	if (is_converted_fd(fd))
		release_converted_fd(fd);
	return original_close(fd);
}


static int bind_before_connect(int fd, const struct sockaddr *addr)
{
	int ret;
	char buf[64];
	struct conv_prefix *cp;

	if (!is_converted_fd(fd) || is_bind_converted_fd(fd))
		return 0;

	sockaddr_ntop(addr, buf, sizeof(buf));

	/* find conv_prefix mathcs for the addr */
	cp = find_conv_prefix(addr);
	if (!cp) {
		pr_e("no matched prefixs for %s", buf);
		return 0;
	}

	pr_vs("use %s for %s", cp->epname, buf);

	/* ok, bind() the fd to converted graft endpoint */
	ret = bind_for_graft_ep(fd, cp->epname);
	if (ret < 0)
		return ret;

	return 0;
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret;

	ret = bind_before_connect(fd, addr);
	if (ret < 0)
		return ret;

	return original_connect(fd, addr, addrlen);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dst, socklen_t addrlen)
{
	int ret;

	ret = bind_before_connect(fd, dst);
	if (ret < 0)
		return ret;

	return original_sendto(fd, buf, len, flags, dst, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	int ret;

	ret = bind_before_connect(fd, msg->msg_name);
	if (ret < 0)
		return ret;

	return original_sendmsg(fd, msg, flags);
	    
}
