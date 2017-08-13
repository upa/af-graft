
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <graft.h>

#define PROGNAME "bind-test"
#include "util.h"


int sso(int sock, int level, int optname, void *optval, socklen_t optlen)
{
	int ret;

	p("call level=%d, opt=%d", level, optname);
	ret = setsockopt(sock, level, optname, optval, optlen);
	if (ret < 0) {
		pr_e("setsockopt failed ret=%d: %s", ret, strerror(errno));
	}
	
	p("setsockopt returns %d", ret);
	p("");
	return ret;
}



int main(int argc, char **argv)
{
	int sock, val, ret, n;
	unsigned int len;
	struct graft_sso_trans *t;
	struct graft_sso_result *r;
	struct sockaddr_gr sgr;
	char buf[GRAFT_SSO_TRANS_SIZE];
	t = (struct graft_sso_trans *)buf;
	memset(buf, 0, sizeof(buf));

	sock = socket(AF_GRAFT, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_e("socket() failed: %s", strerror(errno));
		return -1;
	}

	p("enable delayed execution");
	val = 1;
	ret = sso(sock, IPPROTO_GRAFT, GRAFT_SO_DELAYED, &val, sizeof(val));

	p("SO_REUSEADDR through GRAFT_SO_TRANSPARENT");
	val = 1;
	t->level = SOL_SOCKET;
	t->optname = SO_REUSEADDR;
	t->optlen = sizeof(val);
	memcpy(t->optval, &val, sizeof(val));
	ret = sso(sock, IPPROTO_GRAFT, GRAFT_SO_TRANSPARENT, t, sizeof(buf));


	p("gogo bind!");
	if (!argv[1]) {
		pr_e("to test bind(), specified epname in argv[1]");
		goto out;
	}

	memset(&sgr, 0, sizeof(sgr));
	sgr.sgr_family = AF_GRAFT;
	strncpy(sgr.sgr_epname, argv[1], AF_GRAFT_EPNAME_MAX);
	if (bind(sock, (struct sockaddr *)&sgr, sizeof(sgr)) < 0) {
		pr_e("bind() failed: %s", strerror(errno));
	}
	p("bind success!!");


	p("Check GRAFT_SO_DELAYED_RESULT");
	memset(buf, 0, sizeof(buf));
	len = sizeof(buf);

	ret = getsockopt(sock, IPPROTO_GRAFT, GRAFT_SO_DELAYED_RESULT,
			 buf, &len);
	if (ret < 0) {
		pr_e("obtaining delayed result failed (%d): %s",
		     ret, strerror(errno));
		goto out;
	}

	for (n = len, r = (struct graft_sso_result *)buf;
	     n >= sizeof(struct graft_sso_result);
	     n -= sizeof(struct graft_sso_result)) {
		p("result: level=%d opt=%d ret=%d",
		  r->level, r->optname, r->ret);
		r += 1;
	}


	p("Check GRAFT_SO_DELAYED_RESULT again");
	memset(buf, 0, sizeof(buf));
	len = sizeof(buf);

	ret = getsockopt(sock, IPPROTO_GRAFT, GRAFT_SO_DELAYED_RESULT,
			 buf, &len);
	if (ret < 0) {
		pr_e("obtaining delayed result failed (%d): %s",
		     ret, strerror(errno));
		goto out;
	}

	for (n = len, r = (struct graft_sso_result *)buf;
	     n >= sizeof(struct graft_sso_result);
	     n -= sizeof(struct graft_sso_result)) {
		p("result: level=%d opt=%d ret=%d",
		  r->level, r->optname, r->ret);
		r += 1;
	}


out:
	close(sock);

	return ret;
}
