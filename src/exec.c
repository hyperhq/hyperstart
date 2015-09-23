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

static void pts_hup(struct hyper_event *de, int efd)
{
	struct hyper_pod *pod = de->ptr;
	struct hyper_exec *exec = container_of(de, struct hyper_exec, e);

	fprintf(stdout, "%s\n", __func__);
	hyper_release_exec(exec, pod);
}

static int pts_loop(struct hyper_event *de)
{
	int size = -1;
	struct hyper_buf *buf = &ctl.tty.wbuf;
	struct hyper_exec *exec = container_of(de, struct hyper_exec, e);

	fprintf(stdout, "%s\n", __func__);
	while ((buf->get + 12 < buf->size) && size) {
		size = read(de->fd, buf->data + buf->get + 12, buf->size - buf->get - 12);
		fprintf(stdout, "%s: read %d data\n", __func__, size);
		if (size <= 0) {
			if (errno == EINTR)
				continue;

			if (errno != EAGAIN && errno != EIO) {
				perror("fail to read tty fd");
				return -1;
			}

			if (!exec->exit && size != 0)
				break;

			/* container task exited, No more data from pts of container, release exec */
			size = 0;
			fprintf(stdout, "%s: get eof from pts of contaienr\n", __func__);
		}

		hyper_set_be64(buf->data + buf->get, exec->seq);
		hyper_set_be32(buf->data + buf->get + 8, size + 12);
		buf->get += size + 12;

		dprintf("%s: seq %" PRIu64" len %" PRIu32"\n", __func__, exec->seq, size);
	}

	if (hyper_modify_event(ctl.efd, &ctl.tty, EPOLLIN | EPOLLOUT) < 0) {
		fprintf(stderr, "modify ctl tty event to in & out failed\n");
		return -1;
	}

	return 0;
}

struct hyper_event_ops pts_ops = {
	.read		= pts_loop,
	.hup		= pts_hup,
	.write		= hyper_event_write,
	.wbuf_size	= 512,
	/* don't need read buff, the pts data will store in tty buffer */
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

	e->ptyfd = open(ptmx, O_RDWR | O_NOCTTY);
	fprintf(stdout, "get pty device for exec %s\n", ptmx);

	return 0;
}

int hyper_dup_exec_tty(int to, struct hyper_exec *e)
{
	int fd = -1, ret = -1;
	char pty[128];

	fprintf(stdout, "%s\n", __func__);
	setsid();

	if (e->seq) {
		fd = e->ptyfd;
	} else {
		if (sprintf(pty, "/dev/null") < 0) {
			perror("get pts device name failed");
			goto out;
		}
		fd = open(pty, O_RDWR | O_NOCTTY);
	}

	if (fd < 0) {
		perror("open pty device for execcmd failed");
		goto out;
	}

	if (e->seq && (ioctl(fd, TIOCSCTTY, NULL) < 0)) {
		perror("ioctl pty device for execcmd failed");
		goto out;
	}

	if (hyper_send_type_block(to, READY, 0) < 0) {
		fprintf(stderr, "%s send ready message failed\n", __func__);
		goto out;
	}

	fflush(stdout);

	if (dup2(fd, STDIN_FILENO) < 0) {
		perror("dup tty device to stdin failed");
		goto out;
	}

	if (dup2(fd, STDOUT_FILENO) < 0) {
		perror("dup tty device to stdout failed");
		goto out;
	}

	if (dup2(fd, STDERR_FILENO) < 0) {
		perror("dup tty device to stderr failed");
		goto out;
	}

	ret = 0;
out:
	close(fd);

	return ret;
}

int hyper_watch_exec_pty(struct hyper_exec *exec, struct hyper_pod *pod)
{
	fprintf(stdout, "hyper_init_event container pts event %p, ops %p, fd %d\n",
		&exec->e, &pts_ops, exec->e.fd);

	if (exec->seq == 0)
		return 0;

	if (hyper_init_event(&exec->e, &pts_ops, pod) < 0 ||
	    hyper_add_event(ctl.efd, &exec->e, EPOLLIN) < 0) {
		fprintf(stderr, "add container pts master event failed\n");
		return -1;
	}

	return 0;
}

int hyper_enter_container(struct hyper_pod *pod,
			  struct hyper_exec *exec)
{
	int ipcns, utsns, mntns, ret;
	struct hyper_container *c;
	char path[512];

	ret = ipcns = utsns = mntns = -1;

	c = hyper_find_container(pod, exec->id);
	if (c == NULL) {
		fprintf(stderr, "can not find container %s\n", exec->id);
		return -1;
	}

	sprintf(path, "/proc/%d/ns/uts", pod->init_pid);
	utsns = open(path, O_RDONLY| O_CLOEXEC);
	if (utsns < 0) {
		perror("fail to open utsns of pod init");
		goto out;
	}

	sprintf(path, "/proc/%d/ns/ipc", pod->init_pid);
	ipcns = open(path, O_RDONLY| O_CLOEXEC);
	if (ipcns < 0) {
		perror("fail to open ipcns of pod init");
		goto out;
	}

	mntns = c->ns;
	if (mntns < 0) {
		perror("fail to open mntns of pod init");
		goto out;
	}

	if (setns(utsns, CLONE_NEWUTS) < 0 ||
	    setns(ipcns, CLONE_NEWIPC) <0 ||
	    setns(mntns, CLONE_NEWNS) < 0) {
		perror("fail to enter container ns");
		goto out;
	}

	sprintf(path, "/tmp/hyper/%s/root/%s/", c->id, c->rootfs);
	fprintf(stdout, "root directory for container is %s, exec %s\n",
		path, exec->argv[0]);

	/* TODO: wait for container finishing setup root */
	if (chroot(path) < 0) {
		perror("chroot for exec command failed");
		goto out;
	}

	chdir("/");

	ret = hyper_setup_env(c->envs, c->envs_num);
out:
	close(ipcns);
	close(utsns);

	return ret;
}

struct hyper_exec_arg {
	struct hyper_pod	*pod;
	struct hyper_exec	*exec;
	int			pipe[2];
};

static int hyper_do_exec_cmd(void *data)
{
	struct hyper_exec_arg *arg = data;
	struct hyper_exec *exec = arg->exec;
	struct hyper_pod *pod = arg->pod;
	int pipe[2], pid;

	if (exec->id) {
		char path[512];
		int pidns;

		sprintf(path, "/proc/%d/ns/pid", pod->init_pid);
		pidns = open(path, O_RDONLY| O_CLOEXEC);
		if (pidns < 0) {
			perror("fail to open pidns of pod init");
			_exit(-1);
		}

		/* enter pidns of pod init, so the children of this process will run in
		 * pidns of pod init, see man 2 setns */
		if (setns(pidns, CLONE_NEWPID) < 0) {
			perror("enter pidns of pod init failed");
			_exit(-1);
		}
		close(pidns);
	}

	if (hyper_socketpair(PF_UNIX, SOCK_STREAM, 0, pipe) < 0) {
		perror("create pipe in exec command failed");
		_exit(-1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fail to fork");
		_exit(-1);
	} else if (pid > 0) {
		uint32_t type;

		if (hyper_get_type_block(pipe[0], &type) < 0 || type != READY) {
			fprintf(stderr, "hyper init doesn't get execcmd ready message\n");
			hyper_send_type_block(arg->pipe[1], ERROR, 0);
			goto out;
		}

		if (hyper_send_type_block(arg->pipe[1], READY, 0) < 0) {
			fprintf(stderr, "%s send ready message failed\n", __func__);
			goto out;
		}

		fprintf(stdout, "hyper init get ready message\n");
		exec->pid = pid;
		fprintf(stdout, "create exec cmd %s pid %d\n", exec->argv[0], pid);

		list_add_tail(&exec->list, &pod->exec_head);

		if (hyper_watch_exec_pty(exec, pod) < 0) {
			fprintf(stderr, "add pts master event failed\n");
			goto out;
		}
out:
		close(pipe[0]);
		close(pipe[1]);
		_exit(0);
	}

	if (exec->id && hyper_enter_container(pod, exec) < 0) {
		fprintf(stderr, "enter container ns failed\n");
		_exit(-1);
	}

	if (hyper_dup_exec_tty(pipe[1], exec) < 0) {
		fprintf(stderr, "dup pts to exec stdio failed\n");
		_exit(-1);
	}

	if (execvp(exec->argv[0], exec->argv) < 0) {
		perror("exec failed");
		_exit(-1);
	}

	_exit(0);
}

int hyper_exec_cmd(char *json, int length)
{
	struct hyper_exec *exec;
	struct hyper_pod *pod = &global_pod;
	int stacksize = getpagesize() * 4;
	void *stack = malloc(stacksize);
	struct hyper_exec_arg arg = {
		.pod	= pod,
		.exec	= NULL,
		.pipe	= {-1, -1},
	};
	int pid, ret = -1;
	uint32_t type;

	fprintf(stdout, "call hyper_exec_cmd, json %s, len %d\n", json, length);

	exec = hyper_parse_execcmd(json, length);
	if (exec == NULL) {
		fprintf(stderr, "parse exec cmd failed\n");
		goto out;
	}

	if (exec->argv == NULL) {
		fprintf(stderr, "cmd is %p, seq %" PRIu64 ", container %s\n",
			exec->argv, exec->seq, exec->id);
		goto out;
	}

	if (stack == NULL) {
		perror("fail to allocate stack for container init");
		goto out;
	}

	if (hyper_setup_exec_tty(exec) < 0) {
		fprintf(stderr, "setup exec tty failed\n");
		goto out;
	}

	if (hyper_socketpair(PF_UNIX, SOCK_STREAM, 0, arg.pipe) < 0) {
		perror("create pipe between pod init execcmd failed");
		goto out;
	}

	arg.exec = exec;
	pid = clone(hyper_do_exec_cmd, stack + stacksize, CLONE_VM| CLONE_FILES, &arg);
	free(stack);
	if (pid < 0) {
		perror("clone hyper_do_exec_cmd failed");
		goto out;
	}

	if (hyper_get_type_block(arg.pipe[0], &type) < 0 || type != READY) {
		fprintf(stderr, "hyper init doesn't get execcmd ready message\n");
		return -1;
	}

	ret = 0;
out:
	close(arg.pipe[0]);
	close(arg.pipe[1]);

	return ret;
}

int hyper_release_exec(struct hyper_exec *exec,
		       struct hyper_pod *pod)
{
	int i;

	if (!exec->exit) {
		fprintf(stdout, "first user of exec exit\n");
		exec->exit = 1;
		return 0;
	}

	fprintf(stdout, "second user of exec exit, release\n");
	close(exec->e.fd);
	close(exec->ptyfd);
	hyper_reset_event(&exec->e);

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
			hyper_send_finish(pod);
			//hyper_shutdown(pod);
			return 0;
		}

		if (hyper_start_containers(pod) < 0) {
			fprintf(stderr, "restart container failed\n");
			return -1;
		}

		return 0;
	}

	free(exec->id);

	for (i = 0; i < exec->argc; i++) {
		//fprintf(stdout, "argv %d %s\n", i, exec->argv[i]);
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

	list_for_each_entry(exec, &pod->exec_head, list) {
		fprintf(stdout, "exec seq %" PRIu64 ", seq %" PRIu64 "\n",
			exec->seq, seq);
		if (exec->seq != seq)
			continue;

		return exec;
	}

	return NULL;
}

int hyper_send_exec_eof(int to, struct hyper_pod *pod,
			int pid, uint8_t code)
{
	struct hyper_exec *exec;

	exec = hyper_find_exec_by_pid(&pod->exec_head, pid);
	if (exec == NULL) {
		fprintf(stdout, "can not find exec whose pid is %d\n",
			pid);
		return 0;
	}

	fprintf(stdout, "%s exec exit pid %d, seq %" PRIu64 ", container %s\n",
		__func__, exec->pid, exec->seq, exec->id ? exec->id : "pod");

	exec->code = code;
	hyper_release_exec(exec, pod);

	return 0;
}

void hyper_cleanup_exec(struct hyper_pod *pod)
{
	struct hyper_exec *exec, *next;

	list_for_each_entry_safe(exec, next, &pod->exec_head, list) {
		fprintf(stdout, "cleanup exec seq %" PRIu64 "\n", exec->seq);
		hyper_release_exec(exec, pod);
	}
}
