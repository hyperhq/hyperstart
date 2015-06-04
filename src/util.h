#ifndef _UTIL_H_
#define _UTIL_H_

#include "hyper.h"

char *read_cmdline(void);
int hyper_list_dir(char *path);
int hyper_mkdir(char *path);
int hyper_open_channel(char *channel, int mode);
int hyper_open_serial_dev(char *tty);
int hyper_open_serial(char *tty);
int hyper_setfd_cloexec(int fd);
int hyper_setfd_block(int fd);
int hyper_setfd_nonblock(int fd);
void hyper_shutdown(struct hyper_pod *pod);
void hyper_kill_all(void);
void hyper_unmount_all(void);
#endif
