#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

/*
 * Use raw syscall for versions of glibc that don't include it. But this
 * requires kernel-headers for syscall number hint.
 */

#if !defined SYS_setns && defined __NR_setns
static inline int setns(int fd, int nstype)
{
	errno = syscall(__NR_setns, fd, nstype);
	return errno == 0 ? 0 : -1;
}
#endif
