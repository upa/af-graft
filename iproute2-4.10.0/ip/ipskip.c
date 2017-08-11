/*
 * ipskip.c 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/genetlink.h>

#include <skip.h>

#include "libgenl.h"
#include "utils.h"
#include "ip_common.h"


static struct rtnl_handle genl_rth;
static int genl_family = -1;

static void usage(void) __attribute__((noreturn));


struct skip_param {
	char		name[AF_SKIP_EPNAME_MAX];
	int		family;
	struct in_addr	addr4;
	struct in6_addr	addr6;
	uint16_t	port;	/* 0 means dynamic port range */
};



static int parse_args(int argc, char **argv, struct skip_param *p)
{
	int rc;
	memset(p, 0, sizeof(struct skip_param));

	if (argc == 0)
		usage();

	while(argc > 0) {

		if (strcmp(*argv, "name") == 0) {

			NEXT_ARG();
			if (strlen(*argv) > AF_SKIP_EPNAME_MAX) {
				fprintf(stderr, "endpoint name must be "
					"less than %d characters\n",
					AF_SKIP_EPNAME_MAX);
				exit(-1);
			}
			strncpy(p->name, *argv, AF_SKIP_EPNAME_MAX);

		} else if (strcmp(*argv, "type") == 0) {

			NEXT_ARG();
			if (strcmp(*argv, "ipv4") == 0) {
				p->family = AF_INET;
			} else if (strcmp(*argv, "ipv6") == 0) {
				p->family = AF_INET6;
			} else {
				fprintf(stderr, "invalid type \"%s\"\n",
					*argv);
				exit(-1);
			}

		} else if (strcmp(*argv, "addr") == 0) {

			NEXT_ARG();
			switch(p->family) {
			case AF_INET:
				rc = inet_pton(AF_INET, *argv, &p->addr4);
				if (rc < 1) {
					fprintf(stderr, "invalid ipv4 address"
						"\"%s\"\n", *argv);
					exit(-1);
				}
				break;
			case AF_INET6:
				rc = inet_pton(AF_INET6, *argv, &p->addr6);
				if (rc < 1) {
					fprintf(stderr, "invalid ipv4 address"
						"\"%s\"\n", *argv);
					exit(-1);
				}
				break;
			default :
				fprintf(stderr, "invalid 'type' and 'addr'\n");
				exit(-1);
			}

		} else if (strcmp(*argv, "port") == 0) {

			NEXT_ARG();
			if (strcmp(*argv, "dynamic") == 0) {
				p->port = 0;
			} else {
				p->port = atoi(*argv);
				if (p->port < 0 || p->port > 0xffff) {
					fprintf(stderr,
						"invalid port \"%s\"\n",
						*argv);
					exit(-1);
				}
			}
		}

		argc--;
		argv++;
	}

	return 0;
}




void usage(void)
{
	fprintf(stderr,
		"Usage: ip skip add endpoint name NAME\n"
		"          type { ipv4 | ipv6 } addr ADDR port PORT\n"
		"\n"
		"       ip skip del endpoint name NAME\n"
		"\n"
		"       ip skip show\n"
		"\n"
		"Where: NAME := STRING\n"
		"       ADDR := { IP_ADDRESS }\n"
		"       PORT := { 0..65535 | dynamic }\n"
		);

	exit(-1);
}


static int do_add(int argc, char **argv)
{
	struct skip_param p;
	struct af_skip_endpoint skip_ep;
	struct sockaddr_in *saddr_in;
	struct sockaddr_in6 *saddr_in6;

	if (parse_args(argc, argv, &p) < 0)
		return -1;

	memset(&skip_ep, 0, sizeof(skip_ep));
	strncpy(skip_ep.ssk_epname, p.name, AF_SKIP_EPNAME_MAX);
	
	switch(p.family) {
	case AF_INET :
		saddr_in = (struct sockaddr_in *)&skip_ep.ssk_saddr;
		saddr_in->sin_family = AF_INET;
		saddr_in->sin_port = htons(p.port);
		saddr_in->sin_addr = p.addr4;
		break;

	case AF_INET6:
		saddr_in6 = (struct sockaddr_in6 *)&skip_ep.ssk_saddr;
		saddr_in6->sin6_family = AF_INET6;
		saddr_in6->sin6_port = htons(p.port);
		saddr_in6->sin6_addr = p.addr6;
		/* XXX: should i handle flowinfo and scope_id?*/
		break;
	default :
		fprintf(stderr, "unsupported address family \"%d\"\n",
			p.family);
		exit(-1);
	}


	GENL_REQUEST(req, 1024, genl_family, 0, AF_SKIP_GENL_VERSION,
		     AF_SKIP_CMD_ADD_ENDPOINT, NLM_F_REQUEST | NLM_F_ACK);

	addattr_l(&req.n, 1024, AF_SKIP_ATTR_ENDPOINT, &skip_ep,
		  sizeof(skip_ep));

	if (rtnl_talk(&genl_rth, &req.n, NULL, 0) < 0)
		return -2;

	return 0;
}
	
static int do_del(int argc, char **argv)
{
	struct skip_param p;
	struct af_skip_endpoint skip_ep;

	if (parse_args(argc, argv, &p) < 0)
		return -1;

	memset(&skip_ep, 0, sizeof(skip_ep));
	strncpy(skip_ep.ssk_epname, p.name, AF_SKIP_EPNAME_MAX);

	GENL_REQUEST(req, 1024, genl_family, 0, AF_SKIP_GENL_VERSION,
		     AF_SKIP_CMD_DEL_ENDPOINT, NLM_F_REQUEST | NLM_F_ACK);

	addattr_l(&req.n, 1024, AF_SKIP_ATTR_ENDPOINT, &skip_ep,
		  sizeof(skip_ep));

	if (rtnl_talk(&genl_rth, &req.n, NULL, 0) < 0)
		return -2;

	return 0;
}

static void print_ep(struct af_skip_endpoint *skip_ep)
{
	char buf[64];
	struct sockaddr_in *saddr_in;
	struct sockaddr_in6 *saddr_in6;

	printf("name %s ", skip_ep->ssk_epname);

	switch(skip_ep->ssk_saddr.ss_family) {
	case AF_INET:
		saddr_in = (struct sockaddr_in *)&skip_ep->ssk_saddr;
		inet_ntop(AF_INET, &saddr_in->sin_addr, buf, sizeof(buf));
		printf("type ipv4 ");
		printf("addr %s ", buf);
		if (saddr_in->sin_port == 0)
			printf("port dynamic ");
		else
			printf("port %d ", ntohs(saddr_in->sin_port));
		break;

	case AF_INET6:
		saddr_in6 = (struct sockaddr_in6 *)&skip_ep->ssk_saddr;
		inet_ntop(AF_INET6, &saddr_in6->sin6_addr, buf, sizeof(buf));
		printf("type ipv6 ");
		printf("addr %s ", buf);
		if (saddr_in6->sin6_port == 0)
			printf("port dynamic ");
		else
			printf("port %d ", ntohs(saddr_in6->sin6_port));
		break;

	default:
		printf("type unknown ");
	}

	printf("\n");
}

static int ep_nlmsg(const struct sockaddr_nl *who,
		    struct nlmsghdr *n, void *arg)
{
	struct af_skip_endpoint skip_ep;
	struct genlmsghdr *ghdr;
	struct rtattr *attrs[AF_SKIP_ATTR_MAX + 1];
	int len;

	if (n->nlmsg_type == NLMSG_ERROR)
		return -EBADMSG;

	ghdr = NLMSG_DATA(n);
	len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*ghdr));
	if (len < 0)
		return -1;

	parse_rtattr(attrs, AF_SKIP_ATTR_MAX, (void *)ghdr + GENL_HDRLEN, len);

	if (!attrs[AF_SKIP_ATTR_ENDPOINT]) {
		fprintf(stderr, "%s: endpoint not found in the nlmsg\n",
			__func__);
		return -EBADMSG;
	}

	memcpy(&skip_ep, RTA_DATA(attrs[AF_SKIP_ATTR_ENDPOINT]),
	       sizeof(skip_ep));

	print_ep(&skip_ep);

	return 0;
}

static int do_show(int argc, char **argv)
{
	GENL_REQUEST(req, 128, genl_family, 0,
		     AF_SKIP_GENL_VERSION, AF_SKIP_CMD_GET_ENDPOINT,
		     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST);

	req.n.nlmsg_seq = genl_rth.dump = ++ genl_rth.seq;

	if (rtnl_send(&genl_rth, &req, req.n.nlmsg_len) < 0)
		return -2;

	if (rtnl_dump_filter(&genl_rth, ep_nlmsg, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	return 0;
}

int do_ipskip(int argc, char **argv)
{
	if (argc < 1 || !matches(*argv, "help"))
		usage();

	if (genl_init_handle(&genl_rth, AF_SKIP_GENL_NAME, &genl_family))
		exit(1);

	if (matches(*argv, "add") == 0)
		return do_add(argc - 1, argv + 1);
	if (matches(*argv, "del") == 0 ||
	    matches(*argv, "delete") == 0)
		return do_del(argc - 1, argv + 1);
	if (matches(*argv, "show") == 0)
		return do_show(argc - 1, argv + 1);

	fprintf(stderr,
		"Command \"%s\" is unkonw, type \"ip skip help\".\n", *argv);

	exit(-1);
}
