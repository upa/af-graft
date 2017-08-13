
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <graft.h>

#define PROGNAME "bind-test"
#include "util.h"




int main(int argc, char **argv)
{
	int sock, accept_sock;
	socklen_t len;
	char *epname;
	struct sockaddr_gr saddr_gr;
	struct sockaddr_storage client;

	if (argc < 2) {
		pr_e("usage: %s [ENDPOINT NAME]", argv[0]);
		return -1;
	}
	epname = argv[1];

	memset(&saddr_gr, 0, sizeof(saddr_gr));
	saddr_gr.sgr_family = AF_GRAFT;
	strncpy(saddr_gr.sgr_epname, epname, AF_GRAFT_EPNAME_MAX);
	
	pr("bind graft socket to endpoint '%s'", argv[1]);

	sock = socket(AF_GRAFT, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_e("socket() failed: %s", strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&saddr_gr, sizeof(saddr_gr)) < 0) {
		pr_e("bind() failed: %s", strerror(errno));
		return -1;
	}

	if (listen(sock, 5) < 0) {
		pr_e("listen() failed: %s", strerror(errno));
		return -1;
	}

	while (1) {
		len = sizeof(client);
		accept_sock = accept(sock, (struct sockaddr *)&client, &len);
		if (accept_sock < 0) {
			pr_e("accept() failed: %s", strerror(errno));
			return -1;
		}

		write(accept_sock, "HELLO\n", 6);

		close(accept_sock);
	}

	close(sock);

	return 0;
}
