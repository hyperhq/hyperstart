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
	uint32_t		type;
	/* how many containers are running */
	uint32_t		remains;
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

struct hyper_writter {
	char		*id;
	char		*file;
	uint8_t		*data;
	int		len;
};

struct hyper_ctl {
	int			efd;
	struct hyper_event	tty;
	struct hyper_event	chan;
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

extern struct hyper_pod global_pod;
extern struct hyper_ctl ctl;
extern sigset_t orig_mask;
#endif
