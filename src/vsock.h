#ifndef _VSOCK_H_
#define _VSOCK_H_

#include "event.h"
#include "../config.h"

#ifdef HAVE_VSOCK
int probe_vsock_device(void);
int hyper_create_vsock_listener(unsigned short port);
int hyper_vsock_accept(struct hyper_event *he, int efd,
		       struct hyper_event *ne, struct hyper_event_ops *ops);
#else /*HAVE_VSOCK*/
static int probe_vsock_device(void)
{
	return -1;
}
static int hyper_create_vsock_listener(unsigned short port)
{
	return -1;
}
static int hyper_vsock_accept(struct hyper_event *he, int efd,
		       struct hyper_event *ne, struct hyper_event_ops *ops)
{
	return -1;
}

#endif /*HAVE_VSOCK*/

#endif
