#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include "syscall.h"

#include "hyper.h"
#include "util.h"
#include "parse.h"

static int pts_loop(struct hyper_event *de)
{
	int size = 0;
	uint8_t buf[512];
	uint8_t seq[12];
	struct hyper_exec *exec = container_of(de, struct hyper_exec, e);

	fprintf(stdout, "%s\n", __func__);
	while (1) {
		size = read(de->fd, buf, sizeof(buf));
		if (size <= 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EIO)
				break;

			perror("fail to read tty fd");
			return -1;
		}

		hyper_set_be64(seq, exec->seq);
		hyper_set_be32(seq + 8, size + 12);

		if (hyper_send_data(de->to, seq, 12) < 0)
			continue;

		hyper_send_data(de->to, buf, size);
	}

	return 0;
}

struct hyper_event_ops pts_ops = {
	.read		= pts_loop,
	.hup		= hyper_event_hup,
};

int hyper_setup_exec_tty(struct hyper_exec *e)
{
	int unlock = 0;
	char ptmx[512], path[512];

	if (e->seq == 0)
		return 0;

	if (e->id) {
		if (sprintf(path, "/tmp/hyper/%s/devpts/", e->id) < 0) {
			fprintf(stderr, "get ptmx path failed\n");
			return -1;
		}
	} else {
		if (sprintf(path, "/dev/pts/") < 0) {
			fprintf(stderr, "get ptmx path failed\n");
			return -1;
		}
	}

	if (sprintf(ptmx, "%s/ptmx", path) < 0) {
		fprintf(stderr, "get ptmx path failed\n");
		return -1;
	}

	e->e.fd = open(ptmx, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
	if (e->e.fd < 0) {
		perror("open ptmx device for execcmd failed");
		return -1;
	}

	if (ioctl(e->e.fd, TIOCSPTLCK, &unlock) < 0) {
		perror("ioctl unlock ptmx device failed");
		return -1;
	}

	if (ioctl(e->e.fd, TIOCGPTN, &e->ptyno) < 0) {
		perror("ioctl get execcmd pty device failed");
		return -1;
	}

	if (sprintf(ptmx, "%s/%d", path, e->ptyno) < 0) {
		fprintf(stderr, "get ptmx path failed\n");
		return -1;
	}

	e->pty = strdup(ptmx);
	fprintf(stdout, "get pty device for exec %s\n", e->pty);

	return 0;
}

int hyper_dup_exec_tty(int to, struct hyper_exec *e)
{
	int fd;
	char pty[128];

	setsid();

	if (e->seq) {
		if (sprintf(pty, "/dev/pts/%d", e->ptyno) < 0) {
			perror("get pts device name failed");
			return -1;
		}
	} else {
		if (sprintf(pty, "/dev/null") < 0) {
			perror("get pts device name failed");
			return -1;
		}
	}

	fprintf(stdout, "setup pty device %s for exec\n", pty);

	fd = open(pty, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		perror("open pty device for execcmd failed");
		return -1;
	}

	if (e->seq && (ioctl(fd, TIOCSCTTY, NULL) < 0)) {
		perror("ioctl pty device for execcmd failed");
		return -1;
	}

	if (hyper_send_type_block(to, READY, 0) < 0) {
		fprintf(stderr, "send ready message to hyper init failed\n");
		return -1;
	}

	fflush(stdout);

	if (dup2(fd, STDIN_FILENO) < 0) {
		perror("dup tty device to stdin failed");
		close(fd);
		return -1;
	}

	if (dup2(fd, STDOUT_FILENO) < 0) {
		perror("dup tty device to stdout failed");
		close(fd);
		return -1;
	}

	if (dup2(fd, STDERR_FILENO) < 0) {
		perror("dup tty device to stderr failed");
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}

int hyper_exec_in_container(struct hyper_pod *pod,
			    struct hyper_exec *exec)
{
	global_exec = exec;

	if (hyper_send_type_block(ctl.ctl.fd, EXECCMD, 1) < 0) {
		global_exec = NULL;
		fprintf(stderr, "tell pod init EXECCMD failed\n");
		return -1;
	}

	list_add_tail(&exec->list, &pod->ce_head);
	if (exec->seq == 0)
		return 0;

	fprintf(stdout, "init container exec pts event %p, ops %p, fd %d\n",
		&exec->e, &pts_ops, exec->e.fd);

	if (hyper_init_event(&exec->e, &pts_ops, 0, ctl.tty.fd, NULL) < 0 ||
	    hyper_add_event(ctl.efd, &exec->e) < 0) {
		fprintf(stderr, "add pts master event failed\n");
		return -1;
	}

	return 0;
}

int hyper_request_restart_containers(struct hyper_pod *pod)
{
	int i;
	struct hyper_exec *exec;

	pod->code = 0;
	pod->remains = pod->c_num;

	for (i = 0; i < pod->c_num; i++) {
		exec = &pod->c[i].exec;

		if (hyper_setup_exec_tty(exec) < 0) {
			fprintf(stdout, "restart setup container tty failed\n");
			return -1;
		}
	}

	if (hyper_send_type_block(ctl.ctl.fd, RESTARTCONTAINER, 1) < 0) {
		fprintf(stderr, "tell container init RESTARTCONTAINER failed\n");
		return -1;
	}

	for (i = 0; i < pod->c_num; i++) {
		exec = &pod->c[i].exec;

		list_add_tail(&exec->list, &pod->ce_head);
		if (exec->seq == 0)
			continue;

		if (hyper_init_event(&exec->e, &pts_ops, 0, ctl.tty.fd, NULL) < 0 ||
		    hyper_add_event(ctl.efd, &exec->e) < 0) {
			fprintf(stderr, "add pts master event failed\n");
			return -1;
		}
	}

	return 0;
}

int hyper_exec_cmd(char *json, int length)
{
	struct hyper_exec *exec;
	struct hyper_pod *pod = &global_pod;
	int pid, pipe[2];

	fprintf(stdout, "call hyper_exec_cmd, json %s, len %d\n", json, length);

	exec = hyper_parse_execcmd(json, length);
	if (exec == NULL) {
		fprintf(stderr, "parse exec cmd failed\n");
		return -1;
	}

	if (exec->argv == NULL) {
		fprintf(stderr, "cmd is %p, seq %" PRIu64 ", container %s\n",
			exec->argv, exec->seq, exec->id);
		return -1;
	}

	if (hyper_setup_exec_tty(exec) < 0) {
		fprintf(stderr, "setup exec tty failed\n");
		return -1;
	}

	if (exec->id) {
		if (hyper_exec_in_container(pod, exec) < 0) {
			fprintf(stderr, "notify container exec failed\n");
			return -1;
		}

		return 0;
	}

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, pipe) < 0) {
		perror("create pipe between pod init execcmd failed");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed\n");
		return -1;
	} else if (pid > 0) {
		uint32_t type;

		if (hyper_get_type_block(pipe[0], &type) < 0 || type != READY) {
			fprintf(stderr, "hyper init doesn't get execcmd ready message\n");
			return -1;
		}

		close(pipe[0]);
		close(pipe[1]);
		fprintf(stdout, "hyper init get ready message\n");
		exec->pid = pid;
		fprintf(stdout, "create exec cmd %s pid %d\n", exec->argv[0], pid);

		list_add_tail(&exec->list, &pod->pe_head);
		if (exec->seq == 0)
			return 0;

		fprintf(stdout, "init pod exec pts event %p, ops %p, fd %d\n",
			&exec->e, &pts_ops, exec->e.fd);
		if (hyper_init_event(&exec->e, &pts_ops, 0, ctl.tty.fd, NULL) < 0 ||
		    hyper_add_event(ctl.efd, &exec->e) < 0) {
			fprintf(stderr, "add pts master event failed\n");
			return -1;
		}

		return 0;
	}

	if (hyper_dup_exec_tty(pipe[1], exec) < 0) {
		fprintf(stderr, "dup pts to exec stdio failed\n");
		_exit(-1);
	}

	close(pipe[0]);
	close(pipe[1]);

	if (execvp(exec->argv[0], exec->argv) < 0) {
		perror("exec failed");
		_exit(-1);
	}

	_exit(0);
}

int hyper_container_execcmd(struct hyper_pod *pod)
{
	struct hyper_exec *exec = global_exec;
	struct hyper_container *container = NULL;
	int fd, pid, sock = pod->ctl.fd;
	char root[512]; int pipe[2];

	global_exec = NULL;

	container = hyper_find_container(pod, exec->id);
	if (container == NULL) {
		fprintf(stderr, "can not find container %s\n", exec->id);
		return -1;
	}

	if (sprintf(root, "/tmp/hyper/%s/devpts/", exec->id) < 0) {
		fprintf(stderr, "get container %s pts path failed\n", exec->id);
		return -1;
	}

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, pipe) < 0) {
		perror("create pipe between pod init execcmd failed");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "container init fork failed\n");
		return -1;
	} else if (pid > 0) {
		uint32_t type;

		if (hyper_get_type_block(pipe[0], &type) < 0 || type != READY) {
			fprintf(stderr, "pod init get execcmd ready message failed\n");
			hyper_send_type_block(sock, ERROR, 0);
			return 0;
		}

		close(pipe[0]);
		close(pipe[1]);
		fprintf(stdout, "pod init get ready message\n");

		exec->pid = pid;
		fprintf(stdout, "create exec cmd %s pid %d\n", exec->argv[0], pid);

		if (hyper_send_type_block(sock, ACK, 0) < 0)
			return -1;

		return 0;
	}

	close(pipe[0]);
	sprintf(root, "/proc/%d/ns/mnt", container->exec.pid);

	fprintf(stdout, "container %s, init pid %d\n",
		exec->id, container->exec.pid);

	fd = open(root, O_RDONLY);
	if (fd < 0) {
		perror("fail to open container mnt ns\n");
		goto fail;
	}

	if (syscall(SYS_setns, fd, CLONE_NEWNS) < 0) {
		perror("enter mnt ns failed");
		goto fail;
	}

	close(fd);

	sprintf(root, "/tmp/hyper/%s/root/%s/",
		container->id, container->rootfs);

	fprintf(stdout, "root directory for container is %s, exec %s\n",
		root, exec->argv[0]);

	/* TODO: wait for container finishing setup root */
	if (chroot(root) < 0) {
		perror("chroot for exec command failed");
		goto fail;
	}

	chdir("/");

	if (hyper_dup_exec_tty(pipe[1], exec)) {
		fprintf(stderr, "dup pts to stdio failed\n");
		goto fail;
	}

	close(pipe[1]);
	if (execvp(exec->argv[0], exec->argv) < 0)
		perror("exec failed");

	_exit(-1);
fail:
	hyper_send_type_block(pipe[1], ERROR, 0);
	_exit(-1);
}

int hyper_release_exec(struct hyper_exec *exec,
		       struct hyper_pod *pod)
{
	int i;

	close(exec->e.fd);
	free(exec->pty);

	list_del_init(&exec->list);

	fprintf(stdout, "%s exit code %" PRIu8"\n", __func__, exec->code);
	if (exec->init) {
		fprintf(stdout, "%s container init exited, type %d, remains %d, policy %d\n",
			__func__, pod->type, pod->remains, pod->policy);

		/* stop pod, should not restart container */
		if (pod->type == STOPPOD)
			return 0;

		if (exec->code)
			pod->code = exec->code;

		if (--pod->remains > 0)
			return 0;

		/* should shutdown? */
		if (pod->policy == POLICY_NEVER ||
		   ((pod->policy == POLICY_ONFAILURE) && pod->code == 0)) {
			hyper_shutdown(pod);
			return 0;
		}

		if (hyper_request_restart_containers(pod) < 0) {
			fprintf(stderr, "restart container failed\n");
			return -1;
		}

		return 0;
	}

	free(exec->id);

	for (i = 0; i < exec->argc; i++) {
		fprintf(stdout, "argv %d %s\n", i, exec->argv[i]);
		free(exec->argv[i]);
	}

	free(exec->argv);
	free(exec);

	return 0;
}

struct hyper_exec *hyper_find_exec_by_pid(struct list_head *head, int pid)
{
	struct hyper_exec *exec;

	list_for_each_entry(exec, head, list) {
		fprintf(stdout, "exec pid %d, pid %d\n", exec->pid, pid);
		if (exec->pid != pid)
			continue;

		return exec;
	}

	return NULL;
}

struct hyper_exec *hyper_find_exec_by_seq(struct hyper_pod *pod, uint64_t seq)
{
	struct hyper_exec *exec;

	list_for_each_entry(exec, &pod->ce_head, list) {
		fprintf(stdout, "container exec seq %" PRIu64 ", seq %" PRIu64 "\n",
			exec->seq, seq);
		if (exec->seq != seq)
			continue;

		return exec;
	}

	list_for_each_entry(exec, &pod->pe_head, list) {
		fprintf(stdout, "pod exec seq %" PRIu64 ", seq %" PRIu64 "\n",
			exec->seq, seq);
		if (exec->seq != seq)
			continue;

		return exec;
	}

	return NULL;
}

int hyper_send_exec_eof(int to, struct hyper_pod *pod,
		      struct list_head *head, int pid,
		      uint8_t code)
{
	struct hyper_exec *exec;
	uint8_t seq[12];

	exec = hyper_find_exec_by_pid(head, pid);
	if (exec == NULL) {
		fprintf(stdout, "can not find exec whose pid is %d\n",
			pid);
		return 0;
	}

	fprintf(stdout, "%s exec pid %d, seq %" PRIu64 ", container %s\n",
		__func__, exec->pid, exec->seq, exec->id ? exec->id : "pod");

	exec->code = code;

	if (exec->seq == 0)
		goto out;

	hyper_set_be64(seq, exec->seq);
	hyper_set_be32(seq + 8, 12);
	if (hyper_send_data(to, seq, 12) < 0) {
		fprintf(stderr, "pod signal_loop send finishcmd failed\n");
		return -1;
	}
out:
	hyper_release_exec(exec, pod);

	return 0;
}

void hyper_cleanup_exec(struct hyper_pod *pod)
{
	struct hyper_exec *exec, *next;

	list_for_each_entry_safe(exec, next, &pod->ce_head, list) {
		fprintf(stdout, "cleanup container exec seq %" PRIu64 "\n", exec->seq);
		hyper_release_exec(exec, pod);
	}
}
