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
#include <netdb.h>
#include <linux/genetlink.h>

#include <graft.h>

#include "libgenl.h"
static struct rtnl_handle genl_rth;
static int genl_family = -1;

#define PROGNAME "libgrwrap.so"
#include "../test/util.h"


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
static int (*original_getaddrinfo)(const char *node, const char *service,
				   const struct addrinfo *hints,
				   struct addrinfo **res);
static void (*original_freeaddrinfo)(struct addrinfo *res);


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
	char original[64];	/* original ADDR:PORT=EPNAME string */

	/* for getaddrinfo() conversion */
	char node[64];		/* original address string */
	char serv[64];		/* original portnum string */

	/* for bind() conversion */
	int family;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} addr;
	uint16_t port;
	char epname[AF_GRAFT_EPNAME_MAX];
};
#define MAX_ADDRCONV	64
struct addrconv bind_conv[MAX_ADDRCONV];


int parse_addrconv(char *var, struct addrconv addrconvs[])
{
	/* parse GRAFT_CONV_PAIRS in *vars, add struct addrconv to
	 * *list, and returns the number of parsed pairs */
	int n, i;
	char *p, *tok, *node, *serv, *epname;

	n = 0;
	for (tok = strtok(var, " "); tok != NULL; tok = strtok(NULL, " ")) {
		if (!tok)
			continue;

		node = NULL;
		serv = NULL;
		epname = NULL;

		memset(&addrconvs[n], 0, sizeof(addrconvs[n]));
		strncpy(addrconvs[n].original, tok, 64);

		/* split ADDR:PORT and PENAME by '=' */
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

		/* split ADDR and PORT by ':' */
		for (i = strlen(addrconvs[n].original); i >= 0; i--) {
			p = tok+ i;
			if (*p == ':') {
				*p = '\0';
				serv = p + 1;
				break;
			}
		}
		if (!serv)
			goto err_out;

		/* save strings to addrconv and convert them to binary */
		if (*node == '\0')
			strncpy(addrconvs[n].node, "null", 4);
		else
			strncpy(addrconvs[n].node, node, 64);
		strncpy(addrconvs[n].serv, serv, 64);
		strncpy(addrconvs[n].epname, epname, AF_GRAFT_EPNAME_MAX);

		addrconvs[n].port = htons(atoi(addrconvs[n].serv));

		if (*node == '\0')
			addrconvs[n].family = -1;
		else if (inet_pton(AF_INET, node, &addrconvs[n].addr) == 1)
			addrconvs[n].family = AF_INET;
		else if (inet_pton(AF_INET6, node, &addrconvs[n].addr) == 1)
			addrconvs[n].family = AF_INET6;
		else {
			pr_e("node '%s' serv %s", node, serv);
			goto err_out;
		}

		/*
		pr_e("%d: parsed node:%s serv:%s ep:%s family:%d", n,
		     addrconvs[n].node, addrconvs[n].serv, addrconvs[n].epname,
		     addrconvs[n].family);
		*/
		n++;
	}

	return n;

err_out:
	pr_e("invalid pair '%s'", addrconvs[n].original);
	return -EINVAL;
}



/* retrive all end points through genl */
struct epname_chain {
	char epname[AF_GRAFT_EPNAME_MAX];
	struct epname_chain *next;
};

static int ep_nlmsg(const struct sockaddr_nl *who,
		    struct nlmsghdr *n, void *arg)
{
	struct epname_chain *chain;
	struct graft_genl_endpoint graft_ep;
	struct genlmsghdr *ghdr;
	struct rtattr *attrs[AF_GRAFT_ATTR_MAX + 1];
	int len;

	if (n->nlmsg_type == NLMSG_ERROR)
		return -EBADMSG;

	ghdr = NLMSG_DATA(n);
	len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*ghdr));
	if (len < 0)
		return -1;

	parse_rtattr(attrs, AF_GRAFT_ATTR_MAX,
		     (void *)ghdr + GENL_HDRLEN, len);

	if (!attrs[AF_GRAFT_ATTR_ENDPOINT]) {
		fprintf(stderr, "%s: endpoint not found in the nlmsg\n",
			__func__);
		return -EBADMSG;
	}

	memcpy(&graft_ep, RTA_DATA(attrs[AF_GRAFT_ATTR_ENDPOINT]),
	       sizeof(graft_ep));

	for (chain = arg; chain->next != NULL; chain = chain->next);
	chain->next = (struct epname_chain *)malloc(sizeof(chain));
	chain->next->next = NULL;
	strncpy(chain->next->epname, graft_ep.name, AF_GRAFT_EPNAME_MAX);

	return 0;
}

static struct epname_chain get_epname_chain(void)
{
	struct epname_chain chain;
	memset(&chain, 0, sizeof(chain));
	chain.epname[0] = '\0';

        GENL_REQUEST(req, 128, genl_family, 0,
		     AF_GRAFT_GENL_VERSION, AF_GRAFT_CMD_GET_ENDPOINT,
		     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++genl_rth.seq;

	if (rtnl_send(&genl_rth, &req, req.n.nlmsg_len) < 0) {
		pr_e("rtnl_send failed");
		return chain;
	}

	if (rtnl_dump_filter(&genl_rth, ep_nlmsg, &chain) < 0) {
		pr_e("Dump terminated");
		return chain;
	}

	return chain;
}

static void free_epname_chain(struct epname_chain *chain)
{
	if (chain->next) {
		free_epname_chain(chain->next);
		chain->next = NULL;
	}
	else {
		if (chain->epname[0] == '\0')
			return;
		free(chain);
	}
}


/* Entry Point and Exit Point of LibGrWrapped Application */
__attribute__((constructor))
void libgrwrap_hijack(void)
{
	char buf[1024];

	/* hijacking syscalls */
	original_socket		= dlsym(RTLD_NEXT, "socket");
	original_bind		= dlsym(RTLD_NEXT, "bind");
	original_setsockopt	= dlsym(RTLD_NEXT, "setsockopt");
	original_close		= dlsym(RTLD_NEXT, "close");
	original_bind		= dlsym(RTLD_NEXT, "bind");
	original_connect	= dlsym(RTLD_NEXT, "connect");
	original_sendto		= dlsym(RTLD_NEXT, "sendto");
	original_sendmsg	= dlsym(RTLD_NEXT, "sendmsg");
	original_getaddrinfo	= dlsym(RTLD_NEXT, "getaddrinfo");
	original_freeaddrinfo	= dlsym(RTLD_NEXT, "freeaddrinfo");

	/* check GRAFT disable or not */
	if (getenv(ENV_GRAFT_DISABLED) &&
	    strncmp(getenv(ENV_GRAFT_DISABLED), "disable", 7) == 0)
		set_graft_disabled();

	/* parse address conversion pairs */
	if (getenv(ENV_GRAFT_CONV_PAIRS)) {
		strncpy(buf, getenv(ENV_GRAFT_CONV_PAIRS), sizeof(buf));
		parse_addrconv(buf, bind_conv);
	}

	/* init GENL to gother endname in order to overwrite getaddrinfo */
        if (genl_init_handle(&genl_rth, AF_GRAFT_GENL_NAME, &genl_family)) {
		pr_e("genl init failed");
		exit(1);
	}
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

	switch (domain) {
	case AF_INET:
	case AF_INET6:
		pr_s("overwrite family %d with AF_GRAFT (%d)",
		     domain, AF_GRAFT);
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

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret, val, n;
	struct addrconv *ac, *act;
	struct sockaddr_gr sgr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    addr->sa_family == AF_GRAFT)
		return original_bind(fd, addr, addrlen);

	act = NULL;
	for (n = 0; n < MAX_ADDRCONV && bind_conv[n].family != 0; n++) {
		ac = &bind_conv[n];
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
	if (!act) {
		pr_e("no matched ep for bind() fd=%d", fd);
		return original_bind(fd, addr, addrlen);
	}

	/* create sockaddr_gr and call bind() with it */
	memset(&sgr, 0, sizeof(sgr));
	sgr.sgr_family = AF_GRAFT;
	strncpy(sgr.sgr_epname, act->epname, AF_GRAFT_EPNAME_MAX);

	pr_s("convert bind %s:%s to %s", act->node, act->serv, act->epname);

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

static int bind_before_connect(int fd, char *epname)
{
	int ret, val;
	struct sockaddr_gr sgr;

	/* check is fd already bind()ed */
	if (check_bound_converted_fd(fd))
		return 0;

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
	char *epname;

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    check_bound_converted_fd(fd))
		return original_connect(fd, addr, addrlen);

	epname = getenv(NEV_GRAFT_BIND_BEFORE_CONN);
	if (epname) {
		pr_s("try bind() before connect()");
		ret = bind_before_connect(fd, epname);
		if (ret < 0) {
			pr_e("bind() before connect() failed: %s",
			     strerror(errno));
			return ret;
		}
	}

	return original_connect(fd, addr, addrlen);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, 
	       const struct sockaddr *dest, socklen_t addrlen)
{
	int ret;
	char *epname;

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    check_bound_converted_fd(fd))
		return original_sendto(fd, buf, len, flags, dest, addrlen);

	epname = getenv(NEV_GRAFT_BIND_BEFORE_CONN);
	if (epname) {
		pr_s("try bind() before connect()");
		ret = bind_before_connect(fd, epname);
		if (ret < 0) {
			pr_e("bind() before connect() failed: %s",
			     strerror(errno));
			return ret;
		}
	}

	return original_sendto(fd, buf, len, flags, dest, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	int ret;
	char *epname;

	if (!check_graft_enabled() || !check_converted_fd(fd) ||
	    check_bound_converted_fd(fd))
		return original_sendmsg(fd, msg, flags);

	epname = getenv(NEV_GRAFT_BIND_BEFORE_CONN);
	if (epname) {
		pr_s("try bind() before connect()");
		ret = bind_before_connect(fd, epname);
		if (ret < 0) {
			pr_e("bind() before connect() failed: %s",
			     strerror(errno));
			return ret;
		}
	}

	return original_sendmsg(fd, msg, flags);
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **res)
{
	int ret;
	struct addrinfo *res_gr;
	struct sockaddr_gr *sgr;
	struct addrinfo *rp;
	struct epname_chain chain, *ch;

	if (node == NULL ||
	    (strncmp(node, "graft-", 6) != 0 &&
	     strncmp(node, "graft:", 6) != 0))
		return original_getaddrinfo(node, service, hints, res);

	/* 1st, find epname and check match after 'graft:' */

	chain = get_epname_chain();
	for (ch = chain.next; ch != NULL; ch = ch->next) {
		if (strncmp(ch->epname, node + 6, AF_GRAFT_EPNAME_MAX) == 0) {
			/* this is GRAFT End Point!! */

			pr_s("return sockaddr_gr for %s", node + 6);

			sgr = (struct sockaddr_gr *)malloc(sizeof(*sgr));
			memset(sgr, 0, sizeof(*sgr));
			sgr->sgr_family = AF_GRAFT;
			strncpy(sgr->sgr_epname, node + 6,
				AF_GRAFT_EPNAME_MAX);

			res_gr = (struct addrinfo *)malloc(sizeof(*res_gr));
			memset(res_gr, 0, sizeof(*res_gr));
			res_gr->ai_flags = hints->ai_flags;
			res_gr->ai_family = AF_GRAFT;
			res_gr->ai_socktype = hints->ai_socktype;
			res_gr->ai_protocol = hints->ai_protocol;
			res_gr->ai_addrlen = sizeof(*sgr);
			res_gr->ai_addr = (struct sockaddr *)sgr;
			res_gr->ai_canonname = NULL;	/* XXX */
			res_gr->ai_next = NULL;
			*res = res_gr;

			free_epname_chain(&chain);
			return 0;
		}
	}
	free_epname_chain(&chain);

	/* 2nd, there is no EP name matched to node. leave this to
	 * original getaddrinfo, and overwrite ai_family to AF_GRAFT
	 * for connect(): create socket() with AF_GRAFT and connect()
	 * to sockaddr_in(6).
	 */
	ret = original_getaddrinfo(node + 6, service, hints, res);
	if (ret == 0) {
		for (rp = *res; rp != NULL; rp = rp->ai_next) {
			pr_s("overwrite ai_family of %s to AF_GRAFT", node + 6);
			rp->ai_family = AF_GRAFT;
		}
	}

	return ret;
}

void freeaddrinfo(struct addrinfo *res)
{
	return original_freeaddrinfo(res);
}
