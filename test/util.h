
#include <stdio.h>



#define p(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)

#define pr(fmt, ...) fprintf(stderr,                                  \
			     "\x1b[1m\x1b[34m" PROGNAME ":%d:%s(): " fmt \
			     "\x1b[0m\n",			      \
			     __LINE__, __func__, ##__VA_ARGS__)

/* print success (green) */
#define pr_s(fmt, ...) fprintf(stderr,                                  \
                               "\x1b[1m\x1b[32m" PROGNAME ":%d:%s(): " fmt \
                               "\x1b[0m\n",				\
                               __LINE__, __func__, ##__VA_ARGS__)


/* print error (red) */
#define pr_e(fmt, ...) fprintf(stderr,                                  \
                               "\x1b[1m\x1b[31m" PROGNAME ":%d:%s(): " fmt  \
                               "\x1b[0m\n",                               \
                               __LINE__, __func__, ##__VA_ARGS__)

