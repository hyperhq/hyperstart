#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.h"
#include "event.h"

void hyper_reset_event(struct hyper_event *de)
{
	free(de->buf.data);
	de->buf.data = NULL;
	memset(de, 0, sizeof(*de));
}

int hyper_init_event(struct hyper_event *de,
		   struct hyper_event_ops *ops,
		   uint32_t size, int to, void *arg)
{
	struct hyper_buf *buf = &de->buf;

	memset(buf, 0, sizeof(*buf));

	de->ops		= ops;
	de->ptr		= arg;
	de->to		= to;
	buf->size	= size;

	if (size) {
		buf->data = malloc(size);
		if (buf->data == NULL) {
			fprintf(stderr, "allocate data for event failed\n");
			return -1;
		}
	}

	return 0;
}

int hyper_add_event(int efd, struct hyper_event *de)
{
	struct epoll_event event = {
		.events		= EPOLLIN,
		.data.ptr	= de,
	};

	if (hyper_setfd_nonblock(de->fd) < 0) {
		perror("set fd nonblock failed");
		return -1;
	}

	fprintf(stdout, "%s add event fd %d, %p\n", __func__, de->fd, de->ops);

	if (epoll_ctl(efd, EPOLL_CTL_ADD, de->fd, &event) < 0) {
		perror("epoll_ctl fd failed");
		return -1;
	}

	return 0;
}

void hyper_event_hup(struct hyper_event *de, int efd)
{
	if (epoll_ctl(efd, EPOLL_CTL_DEL, de->fd, NULL) < 0)
		perror("epoll_ctl del epoll event failed");
	close(de->fd);
	hyper_reset_event(de);
}

int hyper_handle_event(int efd, struct epoll_event *event)
{
	struct hyper_event *de = event->data.ptr;

	if (event->events & EPOLLHUP) {
		fprintf(stdout, "%s event EPOLLHUP, de %p, fd %d, %p\n",
			__func__, de, de->fd, de->ops);
		if (de->ops->hup)
			de->ops->hup(de, efd);
		return 0;
	} else if (event->events & EPOLLIN) {
		return de->ops->read(de);
	} else if (event->events & EPOLLERR) {
		fprintf(stderr, "get epoll err of not epool in event\n");
		return -1;
	}

	fprintf(stdout, "%s get unknown event %d\n", __func__, event->events);
	return -1;
}
