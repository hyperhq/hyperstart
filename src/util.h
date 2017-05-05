#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <limits.h>
#include "../config.h"

#define HYPER_EVENTFD_NORMAL 1
#define HYPER_EVENTFD_ERROR INT_MIN

struct hyper_pod;
struct env;

#ifdef WITH_DEBUG
#define dbg_pr(fd, fmt, ...) \
	fprintf(fd, fmt, ##__VA_ARGS__)
#else
#define dbg_pr(fd, fmt, ...) do { } while (0)
#endif

char *read_cmdline(void);
int hyper_setup_env(struct env *envs, int num, bool setPATH);
int hyper_find_sd(char *addr, char **dev);
int hyper_list_dir(char *path);
int hyper_copy_dir(char *src, char *dst);
void hyper_sync_time_hctosys();
void online_cpu(void);
void online_memory(void);
int hyper_cmd(char *cmd);
int hyper_create_file_at(const char *root, char *hyper_path, int size);
void hyper_filize(char *hyper_path);
int hyper_mkdir(char *path, mode_t mode);
int hyper_mkdir_at(const char *root, char *path, int size);
int hyper_write_file(const char *path, const char *value, size_t len);
int hyper_open_channel(char *channel, int mode);
int hyper_setfd_cloexec(int fd);
int hyper_setfd_block(int fd);
int hyper_setfd_nonblock(int fd);
void hyper_shutdown();
void hyper_unmount_all(void);
int hyper_insmod(char *module);
bool hyper_name_to_id(const char *name, unsigned long *val);
struct passwd *hyper_getpwnam(const char *name);
struct group *hyper_getgrnam(const char *name);
int hyper_getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups);
ssize_t nonblock_read(int fd, void *buf, size_t count);
int hyper_mount_nfs(char *server, char *mountpoint);
int64_t hyper_eventfd_recv(int fd);
int hyper_eventfd_send(int fd, int64_t type);
int hyper_mount_blockdev(const char *dev, const char *root, const char *fstype, const char *options);
#endif
