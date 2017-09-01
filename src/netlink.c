#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "event.h"

static int hyper_netlink_expect_dev(int fd, const char *dev)
{
	int len;
	char buf[1024] = {0};

	do {
		len = recv(fd, buf, sizeof(buf), 0);
		if (len < 0)
			break;
		buf[len] = '\0';
		if (dev && strncmp(buf, "add@", strlen("add@")) == 0) {
			fprintf(stdout, "netlink add, expect %s, got %s\n", dev, buf);
			if (strstr(buf, dev) != NULL)
				return 1;
		}
	} while (len > 0);

	return 0;
}

static int hyper_ctlfd_read(struct hyper_event *e, int efd, int events)
{
	return hyper_netlink_expect_dev(e->fd, NULL);
}

static struct hyper_event_ops hyper_devfd_ops = {
	.read		= hyper_ctlfd_read,
};

int hyper_setup_netlink_listener(struct hyper_event *e)
{
	int fd;
	struct sockaddr_nl sa;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = 0xffffffff;
	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
	if (fd < 0) {
		perror("failed to create netlink socket");
		return -1;
	}
	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("failed to bind netlink socket");
		close(fd);
		return -1;
	}
	e->fd = fd;

	if (hyper_init_event(e, &hyper_devfd_ops, NULL) < 0) {
		hyper_reset_event(e);
		return -1;
	}

	return 0;
}

int hyper_netlink_wait_dev(int fd, const char *dev)
{
	struct epoll_event event = {
		.events	= EPOLLIN,
	};
	int efd, n;

	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd < 0) {
		perror("failed to create event poll fd");
		return -1;
	}

	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event) < 0) {
		perror("failed to add fd to epoll");
		goto fail;
	}

	/* SIGCHLD is blocked by hyper_loop() */
	while (1) {
		n = epoll_wait(efd, &event, 1, 2000);
		if (n < 0) {
			perror("fail to wait netlink event");
			goto fail;
		} else if (n == 0) {
			fprintf(stderr, "timeout waiting for device %s\n", dev);
			goto fail;
		}
		if (hyper_netlink_expect_dev(fd, dev) > 0)
			break;
	}

	close(efd);
	return 0;
fail:
	close(efd);
	return -1;
}
