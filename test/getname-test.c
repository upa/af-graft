
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <graft.h>

#define PROGNAME "getname-test"
#include "util.h"

void print_saddr(struct sockaddr *s, socklen_t len)
{
	char buf[64];
	struct sockaddr_in *sin = (struct sockaddr_in *)s;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)s;
	struct sockaddr_un *sun = (struct sockaddr_un *)s;
	struct sockaddr_gr *sgr = (struct sockaddr_gr *)s;

	switch(s->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
		p("AF_INET");
		p("sin_addr: %s", buf);
		p("sin_port: %u", ntohs(sin->sin_port));
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
		p("AF_INET6");
		p("sin6_addr: %s", buf);
		p("sin6_port: %u", ntohs(sin6->sin6_port));
		break;
	case AF_UNIX:
		p("AF_UNIX");
		p("sun_path: %s", sun->sun_path);
		break;
	case AF_GRAFT:
		p("AF_GRAFT");
		p("sgr_epname: %s", sgr->sgr_epname);
		break;
	default:
		p("unknown family %d", s->sa_family);
		break;
	}

	p("addrlen: %u", len);
}

int main(int argc, char **argv)
{
	int sock, ret = 0, val;
	socklen_t len;
	struct sockaddr_storage s;
	struct sockaddr_gr sgr;

	if (!argv[1]) {
		pr_e("usage: %s [endpoint]", PROGNAME);
		return -1;
	}

	sock = socket(AF_GRAFT, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_e("socket() failed %s", strerror(errno));
		return -1;
	}
		
	p("getsockname for unbound graft socket");
	len = sizeof(s);
	memset(&s, 0, len);
	ret = getsockname(sock, (struct sockaddr *)&s, &len);
	if (ret < 0) {
		pr_e("getsockname() failed: %s", strerror(errno));
		goto out;
	}
	print_saddr((struct sockaddr *)&s, len);
	
	p("");
	p("bind() socket to %s", argv[1]);
	memset(&sgr, 0, sizeof(sgr));
	sgr.sgr_family = AF_GRAFT;
	strncpy(sgr.sgr_epname, argv[1], AF_GRAFT_EPNAME_MAX);
	ret = bind(sock, (struct sockaddr *)&sgr, sizeof(sgr));
	if (ret < 0) {
		pr_e("bind() failed :%s", strerror(errno));
		goto out;
	}

	p("");
	p("getsockname for bind()ed graft socket");
	len = sizeof(s);
	memset(&s, 0, len);
	ret = getsockname(sock, (struct sockaddr *)&s, &len);
	if (ret < 0) {
		pr_e("getsockname() failed: %s", strerror(errno));
		goto out;
	}
	print_saddr((struct sockaddr *)&s, len);


	p("");
	p("setsockopt GRAFT_NAME_TRANSPARENT");
	val = 1;
	ret = setsockopt(sock, IPPROTO_GRAFT, GRAFT_NAME_TRANSPARENT,
			 &val, sizeof(val));
	if (ret < 0) {
		pr_e("setsockopt() failed: %s", strerror(errno));
		goto out;
	}


	p("");
	p("getsockname for bind()ed graft socket Again.");
	len = sizeof(s);
	memset(&s, 0, len);
	ret = getsockname(sock, (struct sockaddr *)&s, &len);
	if (ret < 0) {
		pr_e("getsockname() failed: %s", strerror(errno));
		goto out;
	}
	print_saddr((struct sockaddr *)&s, len);
	
	

	p("");
	p("setsockopt GRAFT_NAME_TRANSPARENT off");
	val = 0;
	ret = setsockopt(sock, IPPROTO_GRAFT, GRAFT_NAME_TRANSPARENT,
			 &val, sizeof(val));
	if (ret < 0) {
		pr_e("setsockopt() failed: %s", strerror(errno));
		goto out;
	}


	p("");
	p("getsockname for bind()ed graft socket Again.");
	len = sizeof(s);
	memset(&s, 0, len);
	ret = getsockname(sock, (struct sockaddr *)&s, &len);
	if (ret < 0) {
		pr_e("getsockname() failed: %s", strerror(errno));
		goto out;
	}
	print_saddr((struct sockaddr *)&s, len);
	

out:
	close(sock);
	return ret;
}
