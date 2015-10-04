#ifndef _EXEC_H
#define _EXEC_H

#include "list.h"
#include "event.h"

struct hyper_exec {
	struct list_head	list;
	struct hyper_event	e;
	struct hyper_event	errev;
	char			*id;
	char			**argv;
	int			argc;
	uint64_t		seq;
	uint64_t		errseq;
	int			pid;
	int			ptyno;
	int			init;
	int			ptyfd;
	int			errfd;
	uint8_t			code;
	uint8_t			exit;
};

struct hyper_pod;

int hyper_exec_cmd(char *json, int length);
int hyper_release_exec(struct hyper_exec *, struct hyper_pod *);
int hyper_container_execcmd(struct hyper_pod *pod);
int hyper_setup_exec_tty(struct hyper_exec *e);
int hyper_dup_exec_tty(int fd, struct hyper_exec *e);
struct hyper_exec *hyper_find_exec_by_pid(struct list_head *head, int pid);
struct hyper_exec *hyper_find_exec_by_seq(struct hyper_pod *pod, uint64_t seq);
int hyper_send_exec_eof(int to, struct hyper_pod *pod,
			int pid, uint8_t code);
int hyper_watch_exec_pty(struct hyper_exec *exec, struct hyper_pod *pod);
void hyper_cleanup_exec(struct hyper_pod *pod);

extern struct hyper_event_ops pts_ops;
#endif
