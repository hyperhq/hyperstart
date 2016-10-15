#ifndef _VSOCK_H_
#define _VSOCK_H_

int probe_vsock_device(void);
int hyper_create_vsock_listener(unsigned short port);

#endif
