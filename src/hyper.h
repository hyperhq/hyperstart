#ifndef _HYPER_H_
#define _HYPER_H_

#include <stdint.h>

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
	FINISHCMD,
	READY,
	ACK,
	ERROR,
	WINSIZE,
	PING,
	FINISH,
	NEXT,
	WRITEFILE,
	READFILE,
	NEWCONTAINER,
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
	uint8_t			policy;
	int			efd;
	struct hyper_event	sig;
};

struct hyper_win_size {
	char		*tty;
	int		row;
	int		column;
	uint64_t	seq;
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
	struct hyper_event	sig;
	struct hyper_event	tty;
	struct hyper_event	chan;
};

int hyper_mkdir(char *hyper_path);
int hyper_open_serial(char *tty);
struct hyper_container *hyper_find_container(struct hyper_pod *pod, char *id);
int hyper_start_containers(struct hyper_pod *pod);
void hyper_cleanup_pod(struct hyper_pod *pod);

extern struct hyper_pod global_pod;
extern struct hyper_ctl ctl;
extern struct hyper_exec *global_exec;
#endif
