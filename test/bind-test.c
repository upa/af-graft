
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <skip.h>

#define PROGNAME "bind-test"
#include <skip_util.h>




int main(int argc, char **argv)
{
	int sock, accept_sock;
	socklen_t len;
	char *epname;
	struct sockaddr_skip saddr_sk;
	struct sockaddr_storage client;

	if (argc < 2) {
		pr_e("usage: %s [ENDPOINT NAME]", argv[0]);
		return -1;
	}
	epname = argv[1];

	memset(&saddr_sk, 0, sizeof(saddr_sk));
	saddr_sk.ssk_family = AF_SKIP;
	strncpy(saddr_sk.ssk_epname, epname, AF_SKIP_EPNAME_MAX);
	
	pr("bind skip socket to endpoint '%s'", argv[1]);

	sock = socket(AF_SKIP, SOCK_STREAM, 0);
	if (sock < 0) {
		pr_e("socket() failed: %s", strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&saddr_sk, sizeof(saddr_sk)) < 0) {
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
