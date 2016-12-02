#ifndef _HYPER_H_
#define _HYPER_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "api.h"
#include "net.h"
#include "list.h"
#include "exec.h"
#include "event.h"
#include "container.h"
#include "portmapping.h"

/* Path to rootfs shared directory */
#define SHARED_DIR "/tmp/hyper/shared"

struct hyper_pod {
	struct hyper_interface	*iface;
	struct hyper_route	*rt;
	struct portmapping_white_list	*portmap_white_lists;
	char			**dns;
	struct list_head	containers;
	struct list_head	exec_head;
	char			*hostname;
	char			*share_tag;
	int			init_pid;
	uint32_t		i_num;
	uint32_t		r_num;
	uint32_t		d_num;
	/* how many containers are running */
	uint32_t		remains;
	int			req_destroy;
	int			efd;
};

struct portmapping_white_list {
	char **internal_networks;
	char **external_networks;
	uint32_t i_num;
	uint32_t e_num;
};

struct hyper_win_size {
	int		row;
	int		column;
	uint64_t	seq;
};

struct file_command {
	char		*id;
	char		*file;
};

struct hyper_epoll {
	int			efd;
	struct hyper_event	ctl;
	struct hyper_event	tty;
};

static inline int hyper_symlink(char *oldpath, char *newpath)
{
	return symlink(oldpath, newpath);
}

static inline int hyper_unlink(char *hyper_path)
{
	return unlink(hyper_path);
}

static inline int hyper_create(char *hyper_path)
{
	int fd = creat(hyper_path, 0755);
	if (fd < 0)
		return -1;

	close(fd);
	return 0;
}

int hyper_open_serial(char *tty);
void hyper_cleanup_pod(struct hyper_pod *pod);
int hyper_enter_sandbox(struct hyper_pod *pod, int pidpipe);
void hyper_pod_destroyed(struct hyper_pod *pod, int failed);

extern struct hyper_pod global_pod;
extern struct hyper_epoll hyper_epoll;
extern sigset_t orig_mask;
#endif
