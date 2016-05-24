#ifndef _HYPER_H_
#define _HYPER_H_

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "net.h"
#include "list.h"
#include "exec.h"
#include "event.h"
#include "container.h"

enum {
	RESERVED,
	STARTPOD,
	GETPOD,
	STOPPOD,
	DESTROYPOD,
	RESTARTCONTAINER,
	EXECCMD,
	CMDFINISHED,
	READY,
	ACK,
	ERROR,
	WINSIZE,
	PING,
	PODFINISHED,
	NEXT,
	WRITEFILE,
	READFILE,
	NEWCONTAINER,
	KILLCONTAINER,
	ONLINECPUMEM,
	SETUPINTERFACE,
	CONTAINERFINISHED,
};

enum {
	POLICY_NEVER,
	POLICY_ALWAYS,
	POLICY_ONFAILURE,
};

struct hyper_pod {
	struct hyper_container	*c;
	struct hyper_interface	*iface;
	struct hyper_route	*rt;
	char			**dns;
	struct list_head	containers;
	struct list_head	exec_head;
	char			*hostname;
	char			*share_tag;
	int			init_pid;
	uint32_t		i_num;
	uint32_t		r_num;
	uint32_t		e_num;
	uint32_t		d_num;
	uint32_t		type;
	/* how many containers are running */
	uint32_t		remains;
	/* increase only container index */
	uint32_t		c_idx;
	uint8_t			policy;
	int			efd;
};

struct hyper_win_size {
	char		*tty;
	int		row;
	int		column;
	uint64_t	seq;
};

struct hyper_killer {
	char		*id;
	int		signal;
};

struct hyper_reader {
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

int hyper_mkdir(char *hyper_path);
int hyper_open_serial(char *tty);
struct hyper_container *hyper_find_container(struct hyper_pod *pod, char *id);
int hyper_start_containers(struct hyper_pod *pod);
void hyper_cleanup_pod(struct hyper_pod *pod);

extern struct hyper_pod global_pod;
extern struct hyper_ctl ctl;
extern struct hyper_exec *global_exec;
#endif
