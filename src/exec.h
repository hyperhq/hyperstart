#ifndef _EXEC_H
#define _EXEC_H

#include "list.h"
#include "event.h"

struct env {
	char	*env;
	char	*value;
};

struct hyper_exec {
	struct list_head	list;
	struct hyper_pod	*pod;

	struct hyper_event	stdinev;
	struct hyper_event	stdoutev;
	struct hyper_event	stderrev;
	int			pid;
	int			ptyno;
	int			init;
	int			ptyfd;
	int			stdinfd;
	int			stdoutfd;
	int			stderrfd;
	uint8_t			close_stdin_request;
	uint8_t			code;
	uint8_t			exit;
	uint8_t			ref;

	// configs
	char			*container_id;
	char			*user;
	char			*group;
	char			**additional_groups;
	int			nr_additional_groups;
	struct env		*envs;
	int			envs_num;
	char			**argv;
	int			argc;
	int			tty; // use tty or not
	uint64_t		seq;
	uint64_t		errseq;
	char			*workdir;
};

struct hyper_pod;

int hyper_exec_cmd(char *json, int length);
int hyper_run_process(struct hyper_exec *e);
struct hyper_exec *hyper_find_exec_by_pid(struct list_head *head, int pid);
struct hyper_exec *hyper_find_exec_by_seq(struct hyper_pod *pod, uint64_t seq);
int hyper_handle_exec_exit(struct hyper_pod *pod, int pid, uint8_t code);

#endif
