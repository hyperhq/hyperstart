#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "net.h"
#include "util.h"
#include "hyper.h"
#include "event.h"

void hyper_reset_event(struct hyper_event *he)
{
	free(he->rbuf.data);
	free(he->wbuf.data);
	close(he->fd);
	memset(he, 0, sizeof(*he));
	he->fd = -1;
}

int hyper_init_event(struct hyper_event *he, struct hyper_event_ops *ops, void *arg)
{
	struct hyper_buf *rbuf = &he->rbuf;
	struct hyper_buf *wbuf = &he->wbuf;

	memset(rbuf, 0, sizeof(*rbuf));
	memset(wbuf, 0, sizeof(*wbuf));

	he->ops		= ops;
	he->ptr		= arg;
	rbuf->size	= ops->rbuf_size;
	wbuf->size	= ops->wbuf_size;

	if (rbuf->size) {
		rbuf->data = malloc(rbuf->size);
		if (rbuf->data == NULL) {
			fprintf(stderr, "allocate read buffer for event failed\n");
			return -1;
		}
	}

	if (wbuf->size) {
		wbuf->data = malloc(wbuf->size);
		if (wbuf->data == NULL) {
			fprintf(stderr, "allocate write buffer for event failed\n");
			return -1;
		}
	}

	return 0;
}

int hyper_add_event(int efd, struct hyper_event *he, int flag)
{
	struct epoll_event event = {
		.events		= flag,
		.data.ptr	= he,
	};

	he->flag = flag;
	if (hyper_setfd_nonblock(he->fd) < 0) {
		perror("set fd nonblock failed");
		return -1;
	}

	fprintf(stdout, "%s add event fd %d, %p\n", __func__, he->fd, he->ops);

	if (epoll_ctl(efd, EPOLL_CTL_ADD, he->fd, &event) < 0) {
		perror("epoll_ctl fd failed");
		return -1;
	}

	return 0;
}

int hyper_modify_event(int efd, struct hyper_event *he, int flag)
{
	struct epoll_event event = {
		.events		= flag,
		.data.ptr	= he,
	};

	if (he->flag == flag)
		return 0;

	he->flag = flag;
	fprintf(stdout, "%s modify event fd %d, %p, event %d\n",
			__func__, he->fd, he, flag);

	if (epoll_ctl(efd, EPOLL_CTL_MOD, he->fd, &event) < 0) {
		perror("epoll_ctl fd failed");
		return -1;
	}

	return 0;
}

int hyper_wbuf_append_msg(struct hyper_event *he, uint8_t *data, uint32_t len)
{
	struct hyper_buf *buf = &he->wbuf;

	if (buf->get + len > buf->size) {
		uint8_t *data;
		fprintf(stdout, "%s: tty buf full\n", __func__);

		data = realloc(buf->data, buf->size + len);
		if (data == NULL) {
			perror("realloc failed");
			return -1;
		}
		buf->data = data;
		buf->size += len;
	}

	memcpy(buf->data + buf->get, data, len);
	buf->get += len;

	hyper_modify_event(hyper_epoll.efd, he, he->flag| EPOLLOUT);
	return 0;
}

int hyper_requeue_event(int efd, struct hyper_event *ev)
{
	struct epoll_event event = {
		.events		= ev->flag,
		.data.ptr	= ev,
	};

	if (epoll_ctl(efd, EPOLL_CTL_DEL, ev->fd, NULL) < 0) {
		perror("epoll_ctl del fd failed");
		return -1;
	}

	if (epoll_ctl(efd, EPOLL_CTL_ADD, ev->fd, &event) < 0) {
		perror("epoll_ctl add fd failed");
		return -1;
	}

	return 0;
}

int hyper_event_write(struct hyper_event *he, int efd, int events)
{
	struct hyper_buf *buf = &he->wbuf;
	uint32_t len = 0;
	int size = 0;

	while (len < buf->get) {
		size = write(he->fd, buf->data + len, buf->get - len);
		if (size <= 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || size == 0)
				break;
			return -1;
		}
		len += size;
	}

	buf->get -= len;
	memmove(buf->data, buf->data + len, buf->get);

	if (buf->get == 0) {
		hyper_modify_event(hyper_epoll.efd, he, he->flag & ~EPOLLOUT);
	}

	return 0;
}

void hyper_event_hup(struct hyper_event *he, int efd)
{
	if (epoll_ctl(efd, EPOLL_CTL_DEL, he->fd, NULL) < 0)
		perror("epoll_ctl del epoll event failed");
	hyper_reset_event(he);
}

int hyper_handle_event(int efd, struct epoll_event *event)
{
	struct hyper_event *he = event->data.ptr;
	fprintf(stdout, "%s get event %d, he %p, fd %d. ops %p\n",
			__func__, event->events, he, he->fd, he->ops);

	/* do not handle hup event if have in/out event */
	if ((event->events & EPOLLIN) && he->ops->read) {
		fprintf(stdout, "%s event EPOLLIN, he %p, fd %d, %p\n",
			__func__, he, he->fd, he->ops);
		return he->ops->read(he, efd, event->events);
	}
	if ((event->events & EPOLLOUT) && he->ops->write) {
		fprintf(stdout, "%s event EPOLLOUT, he %p, fd %d, %p\n",
			__func__, he, he->fd, he->ops);
		return he->ops->write(he, efd, event->events);
	}

	if ((event->events & EPOLLHUP) || (event->events & EPOLLERR)) {
		fprintf(stdout, "%s event EPOLLHUP or EPOLLERR, he %p, fd %d, %x\n",
			__func__, he, he->fd, event->events);
		if (he->ops->hup)
			he->ops->hup(he, efd);
	}

	return 0;
}
