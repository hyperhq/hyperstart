#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include "../config.h"

struct hyper_pod;
struct env;

#ifdef WITH_DEBUG
#define dprintf(fmt, ...) \
	fprintf(stdout, fmt, ##__VA_ARGS__)
#else
#define dprintf(fmr, ...)
#endif

char *read_cmdline(void);
int hyper_setup_env(struct env *envs, int num);
int hyper_find_sd(char *addr, char **dev);
int hyper_list_dir(char *path);
int hyper_copy_dir(char *src, char *dst);
void hyper_sync_time_hctosys();
void online_cpu(void);
void online_memory(void);
int hyper_cmd(char *cmd);
int hyper_create_file(const char *hyper_path);
void hyper_filize(char *hyper_path);
int hyper_mkdir(char *path, mode_t mode);
int hyper_write_file(const char *path, const char *value, size_t len);
int hyper_open_channel(char *channel, int mode);
int hyper_setfd_cloexec(int fd);
int hyper_setfd_block(int fd);
int hyper_setfd_nonblock(int fd);
int hyper_socketpair(int domain, int type, int protocol, int sv[2]);
void hyper_shutdown();
void hyper_unmount_all(void);
int hyper_insmod(char *module);
bool hyper_name_to_id(const char *name, unsigned long *val);
struct passwd *hyper_getpwnam(const char *name);
struct group *hyper_getgrnam(const char *name);
int hyper_getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups);
ssize_t nonblock_read(int fd, void *buf, size_t count);
int hyper_mount_nfs(char *server, char *mountpoint);
#endif
