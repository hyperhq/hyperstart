#ifndef _NETLINK_H_
#define _NETLINK_H_

int hyper_setup_netlink_listener(struct hyper_event *e);
int hyper_netlink_wait_dev(int fd, const char *dev);
#endif
