#ifndef _DVM_H_
#define _DVM_H_

#include <stdint.h>

#include "net.h"
#include "list.h"
#include "exec.h"
#include "event.h"
#include "container.h"

enum {
	SETDVM,
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
	struct list_head	pe_head;
	struct list_head	ce_head;
	char			*hostname;
	char			*tag;
	int			init_pid;
	uint32_t		c_num;
	uint32_t		i_num;
	uint32_t		r_num;
	uint32_t		e_num;
	uint32_t		type;
	uint32_t		code;
	uint32_t		remains;
	uint8_t			policy;
	int			efd;
	struct hyper_event	sig;
	struct hyper_event	ctl;
};

struct hyper_win_size {
	char		*tty;
	int		row;
	int		column;
	uint64_t	seq;
};

struct hyper_ctl {
	int			efd;
	struct hyper_event	sig;
	struct hyper_event	tty;
	struct hyper_event	chan;
	struct hyper_event	ctl;
};

int hyper_mkdir(char *hyper_path);
int hyper_open_serial(char *tty);
struct hyper_container *hyper_find_container(struct hyper_pod *pod, char *id);

extern struct hyper_pod global_pod;
extern struct hyper_ctl ctl;
extern struct hyper_exec *global_exec;
#endif
