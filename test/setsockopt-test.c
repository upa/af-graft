
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <graft.h>

#define PROGNAME "bind-test"
#include <graft_util.h>




int main(int argc, char **argv)
{
	int ret, sock, level, optname, optval;

	if (argc < 4) {
		pr_e("usage: %s level optname value (all int)", argv[0]);
		return -1;
	}
	
	level	= atoi(argv[1]);
	optname = atoi(argv[2]);
	optval	= atoi(argv[3]);

	sock = socket(AF_GRAFT, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_e("socket() failed: %s", strerror(errno));
		return -1;
	}

	pr("fd=%d, level=%d, optname=%d, optval=%d",
	   sock, level, optname, optval);

	ret = setsockopt(sock, level, optname, &optval, sizeof(optval));
	if (ret < 0) {
		pr_e("setsockopt failed ret=%d: %s", ret, strerror(errno));
	}
	
	pr("setsockopt returns %d", ret);

	close(sock);

	return ret;
}
