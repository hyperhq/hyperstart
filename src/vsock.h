#ifndef _VSOCK_H_
#define _VSOCK_H_

int probe_vsock_device(void);
int hyper_create_vsock_listener(unsigned short port);
int hyper_vsock_accept(struct hyper_event *he, int efd);

#endif
