#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <dirent.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <inttypes.h>
#include <grp.h>
#include <pwd.h>

#include "hyper.h"
#include "util.h"
#include "parse.h"
#include "syscall.h"

struct stdio_config {
	int stdinfd, stdoutfd, stderrfd;
	int stdinevfd, stdoutevfd, stderrevfd;
};

static int hyper_release_exec(struct hyper_exec *);
static void hyper_exec_process(struct hyper_exec *exec, int pipe, struct stdio_config *io);

static int send_exec_finishing(uint64_t seq, int len, int code)
{
	int ret = -1;
	uint8_t *data = malloc(len);
	if (data == NULL) {
		goto fail;
	}

	/* no in event, no more data, send eof */
	hyper_set_be64(data, seq);
	hyper_set_be32(data + 8, len);
	if (len > 12)
		data[12] = code;

	ret = hyper_wbuf_append_msg(&hyper_epoll.tty, data, len);
fail:
	free(data);
	return ret;
}

static int hyper_send_exec_eof(struct hyper_exec *exec) {
	return send_exec_finishing(exec->seq, 12, -1);
}

static int hyper_send_exec_code(struct hyper_exec *exec) {
	char *pae; // ProcessAsyncEvent
#define PAE "{\"container\":\"%s\",\"process\":\"%s\",\"event\":\"finished\",\"status\":%d}"
	if (asprintf(&pae, PAE, exec->container_id, exec->id, exec->code) < 0) {
		return -1;
	}
#undef PAE
	return hyper_ctl_append_msg(&hyper_epoll.ctl, PROCESSASYNCEVENT, (uint8_t *)pae, strlen(pae));
}

static void pts_hup(struct hyper_event *de, int efd, struct hyper_exec *exec)
{
	hyper_event_hup(de, efd);
	hyper_release_exec(exec);
}

static void stdin_hup(struct hyper_event *de, int efd)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stdinev);
	fprintf(stdout, "%s, seq %" PRIu64", id %s\n", __func__, exec->seq, exec->id);
	return pts_hup(de, efd, exec);
}

static void stdout_hup(struct hyper_event *de, int efd)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stdoutev);
	fprintf(stdout, "%s, seq %" PRIu64", id %s\n", __func__, exec->seq, exec->id);
	return pts_hup(de, efd, exec);
}

static void stderr_hup(struct hyper_event *de, int efd)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stderrev);
	fprintf(stdout, "%s, seq %" PRIu64", id %s\n", __func__, exec->seq, exec->id);
	return pts_hup(de, efd, exec);
}

static int pts_loop(struct hyper_event *de, uint64_t seq, int efd, struct hyper_exec *exec)
{
	int size = -1;
	int flag = de->flag | EPOLLOUT;
	struct hyper_buf *buf = &hyper_epoll.tty.wbuf;

	if (FULL(buf)) {
		goto out;
	}

	do {
		size = read(de->fd, buf->data + buf->get + 12, buf->size - buf->get - 12);
		if (size < 0) {
			if (errno == EINTR)
				continue;

			if (errno != EAGAIN && errno != EIO) {
				perror("failed to read process's stdout/stderr");
				pts_hup(de, efd, exec);
				return 0;
			}

			break;
		}
		fprintf(stdout, "%s: read %d data\n", __func__, size);

		if (size == 0) { // eof
			pts_hup(de, efd, exec);
			return 0;
		}

		hyper_set_be64(buf->data + buf->get, seq);
		hyper_set_be32(buf->data + buf->get + 8, size + 12);
		buf->get += size + 12;
	} while (!FULL(buf));

	if (FULL(buf)) {
		/* del & add event to move event to tail, this gives
		 * other event a chance to write data to wbuf of tty. */
		hyper_requeue_event(hyper_epoll.efd, de);
	}
out:
	if (hyper_modify_event(hyper_epoll.efd, &hyper_epoll.tty, flag) < 0) {
		fprintf(stderr, "modify tty event to %d failed\n", flag);
		return -1;
	}

	return 0;
}

static int write_to_stdin(struct hyper_event *de, int efd, int events)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stdinev);
	fprintf(stdout, "%s, seq %" PRIu64"\n", __func__, exec->seq);

	if (hyper_event_write(de, efd, events) < 0 || (de->wbuf.get == 0 && exec->close_stdin_request))
		pts_hup(de, efd, exec);

	return 0;
}

struct hyper_event_ops in_ops = {
	.hup		= stdin_hup,
	.write		= write_to_stdin,
	.wbuf_size	= 512,
};

static int stdout_loop(struct hyper_event *de, int efd, int events)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stdoutev);
	fprintf(stdout, "%s, seq %" PRIu64"\n", __func__, exec->seq);

	return pts_loop(de, exec->seq, efd, exec);
}

struct hyper_event_ops out_ops = {
	.read		= stdout_loop,
	.hup		= stdout_hup,
	/* don't need read buff, the pts data will store in tty buffer */
	/* don't need write buff, the stdout data is one way */
};

static int stderr_loop(struct hyper_event *de, int efd, int events)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stderrev);
	fprintf(stdout, "%s, seq %" PRIu64"\n", __func__, exec->errseq);

	return pts_loop(de, exec->errseq ? exec->errseq : exec->seq, efd, exec);
}

struct hyper_event_ops err_ops = {
	.read		= stderr_loop,
	.hup		= stderr_hup,
	/* don't need read buff, the stderr data will store in tty buffer */
	/* don't need write buff, the stderr data is one way */
};

static int hyper_setup_exec_user(struct hyper_exec *exec)
{
	char *user = exec->user == NULL || strlen(exec->user) == 0 ? NULL : exec->user;
	char *group = exec->group == NULL || strlen(exec->group) == 0 ? NULL : exec->group;

	uid_t uid = 0;
	gid_t gid = 0;
	int ngroups;
	gid_t *reallocgroups, *groups = NULL;

	// check the config
	if (!user && !group && exec->nr_additional_groups == 0) {
		return 0;
	}

	// get uid
	if (user) {
		fprintf(stdout, "try to find the user: %s\n", user);
		struct passwd *pwd = hyper_getpwnam(user);
		if (pwd == NULL) {
			perror("can't find the user");
			unsigned long id;
			if (!hyper_name_to_id(user, &id))
				return -1;
			uid = id;
			gid = 0;
			goto setup;
		}
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;

		// get groups of user
		groups = malloc(sizeof(gid_t) * 10);
		if (groups == NULL) {
			goto fail;
		}
		if (hyper_getgrouplist(pwd->pw_name, gid, groups, &ngroups) < 0) {
			reallocgroups = realloc(groups, sizeof(gid_t) * ngroups);
			if (reallocgroups == NULL) {
				goto fail;
			}
			groups = reallocgroups;
			if (hyper_getgrouplist(pwd->pw_name, gid, groups, &ngroups) < 0) {
				goto fail;
			}
		}

		// set user related envs. the container env config can overwrite it
		setenv("USER", pwd->pw_name, 1);
		setenv("HOME", pwd->pw_dir, 1);
	} else {
		ngroups = getgroups(0, NULL);
		if (ngroups < 0) {
			goto fail;
		}
		groups = malloc(sizeof(gid_t) * ngroups);
		if (groups == NULL) {
			goto fail;
		}
		ngroups = getgroups(ngroups, groups);
		if (ngroups < 0) {
			goto fail;
		}
	}

	// get gid
	if (group) {
		fprintf(stdout, "try to find the group: %s\n", group);
		struct group *gr = hyper_getgrnam(group);
		if (gr == NULL) {
			perror("can't find the group");
			return -1;
		}
		gid = gr->gr_gid;
	}

	// append additional groups to supplementary groups
	int i;
	reallocgroups = realloc(groups, sizeof(gid_t) * (ngroups + exec->nr_additional_groups));
	if (reallocgroups == NULL)
		goto fail;
	groups = reallocgroups;
	for (i = 0; i < exec->nr_additional_groups; i++) {
		unsigned long id;
		fprintf(stdout, "try to find the group: %s\n", exec->additional_groups[i]);
		if (hyper_name_to_id(exec->additional_groups[i], &id)) {
			groups[ngroups] = id;
		} else {
			struct group *gr = hyper_getgrnam(exec->additional_groups[i]);
			if (gr == NULL) {
				perror("can't find the group");
				goto fail;
			}
			groups[ngroups] = gr->gr_gid;
		}
		ngroups++;
	}

setup:
	// setup the owner of tty
	if (exec->tty) {
		char ptmx[512];
		sprintf(ptmx, "/dev/pts/%d", exec->ptyno);
		if (chown(ptmx, uid, gid) < 0) {
			perror("failed to change the owner for the slave pty file");
			goto fail;
		}
	}

	// apply
	if (groups && setgroups(ngroups, groups) < 0) {
		perror("setgroups() fails");
		goto fail;
	}
	if (setgid(gid) < 0) {
		perror("setgid() fails");
		goto fail;
	}
	if (setuid(uid) < 0) {
		perror("setuid() fails");
		goto fail;
	}
	free(groups);
	return 0;
fail:
	free(groups);
	return -1;
}

static int hyper_setup_stdio_notty(struct hyper_exec *e, struct stdio_config *io)
{
	if (e->errseq == 0)
		return -1;

	int inpipe[2];
	if (pipe2(inpipe, O_CLOEXEC) < 0) {
		fprintf(stderr, "creating stderr pipe failed\n");
		return -1;
	}
	hyper_setfd_nonblock(inpipe[1]);
	io->stdinevfd = inpipe[1];
	io->stdinfd = inpipe[0];

	int outpipe[2];
	if (pipe2(outpipe, O_CLOEXEC) < 0) {
		fprintf(stderr, "creating stderr pipe failed\n");
		return -1;
	}
	hyper_setfd_nonblock(outpipe[0]);
	io->stdoutevfd = outpipe[0];
	io->stdoutfd = outpipe[1];

	int errpipe[2];
	if (pipe2(errpipe, O_CLOEXEC) < 0) {
		fprintf(stderr, "creating stderr pipe failed\n");
		return -1;
	}
	hyper_setfd_nonblock(errpipe[0]);
	io->stderrevfd = errpipe[0];
	io->stderrfd = errpipe[1];

	return 0;
}

static int hyper_setup_stdio(struct hyper_exec *e, struct stdio_config *io)
{
	int unlock = 0;
	int ptymaster;
	char ptmx[512];

	if (!e->tty) { // don't use tty for stdio
		return hyper_setup_stdio_notty(e, io);
	}

	if (e->errseq > 0) {
		int errpipe[2];
		if (pipe2(errpipe, O_CLOEXEC) < 0) {
			fprintf(stderr, "creating stderr pipe failed\n");
			return -1;
		}
		hyper_setfd_nonblock(errpipe[0]);
		io->stderrevfd = errpipe[0];
		io->stderrfd = errpipe[1];
	}

	if (sprintf(ptmx, "/tmp/hyper/%s/devpts/ptmx", e->container_id) < 0) {
		fprintf(stderr, "get ptmx path failed\n");
		return -1;
	}

	ptymaster = open(ptmx, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
	if (ptymaster < 0) {
		perror("open ptmx device for execcmd failed");
		return -1;
	}

	if (ioctl(ptymaster, TIOCSPTLCK, &unlock) < 0) {
		perror("ioctl unlock ptmx device failed");
		close(ptymaster);
		return -1;
	}

	if (ioctl(ptymaster, TIOCGPTN, &e->ptyno) < 0) {
		perror("ioctl get execcmd pty device failed");
		close(ptymaster);
		return -1;
	}

	e->ptyfd = ptymaster;
	return 0;
}

static int hyper_install_process_stdio(struct hyper_exec *e, struct stdio_config *io)
{
	int ret = -1;

	fprintf(stdout, "%s\n", __func__);

	if (e->tty) {
		char ptmx[512];
		int ptyslave;

		sprintf(ptmx, "/dev/pts/%d", e->ptyno);
		ptyslave = open(ptmx, O_RDWR | O_CLOEXEC);
		if (ptyslave < 0 || ioctl(ptyslave, TIOCSCTTY, NULL) < 0) {
			perror("ioctl pty device for execcmd failed");
			goto out;
		}
		io->stdinfd = ptyslave;
		io->stdoutfd = ptyslave;
		if (e->errseq == 0)
			io->stderrfd = ptyslave;
	}

	fflush(NULL);

	if (dup2(io->stdinfd, STDIN_FILENO) < 0) {
		perror("dup tty device to stdin failed");
		goto out;
	}

	if (dup2(io->stdoutfd, STDOUT_FILENO) < 0) {
		perror("dup tty device to stdout failed");
		goto out;
	}

	if (dup2(io->stderrfd, STDERR_FILENO) < 0) {
		perror("dup err pipe to stderr failed");
		goto out;
	}

	/*
	 * we are going to execvp(), all of the io->stdinfd, io->stdoutfd and
	 * io->stderrfd are O_CLOEXEC, we don't need to close them explicitly
	 */
	ret = 0;
out:
	return ret;
}

static int hyper_setup_stdio_events(struct hyper_exec *exec, struct stdio_config *io)
{
	if (exec->tty) {
		io->stdinevfd = dup(exec->ptyfd);
		hyper_setfd_cloexec(io->stdinevfd);
		io->stdoutevfd = dup(exec->ptyfd);
		hyper_setfd_cloexec(io->stdoutevfd);
		if (exec->errseq == 0) {
			io->stderrevfd = dup(exec->ptyfd);
			hyper_setfd_cloexec(io->stderrevfd);
		}
	}

	fprintf(stdout, "hyper_init_event exec stdin event %p, ops %p, fd %d\n",
		&exec->stdinev, &in_ops, io->stdinevfd);
	exec->stdinev.fd = io->stdinevfd;
	if (hyper_init_event(&exec->stdinev, &in_ops, NULL) < 0 ||
	    hyper_add_event(hyper_epoll.efd, &exec->stdinev, EPOLLOUT) < 0) {
		fprintf(stderr, "add container stdin event failed\n");
		return -1;
	}
	exec->ref++;

	fprintf(stdout, "hyper_init_event exec stdout event %p, ops %p, fd %d\n",
		&exec->stdoutev, &out_ops, io->stdoutevfd);
	exec->stdoutev.fd = io->stdoutevfd;
	if (hyper_init_event(&exec->stdoutev, &out_ops, NULL) < 0 ||
	    hyper_add_event(hyper_epoll.efd, &exec->stdoutev, EPOLLIN) < 0) {
		fprintf(stderr, "add container stdout event failed\n");
		return -1;
	}
	exec->ref++;

	fprintf(stdout, "hyper_init_event exec stderr event %p, ops %p, fd %d\n",
		&exec->stderrev, &err_ops, io->stderrevfd);
	exec->stderrev.fd = io->stderrevfd;
	if (hyper_init_event(&exec->stderrev, &err_ops, NULL) < 0 ||
	    hyper_add_event(hyper_epoll.efd, &exec->stderrev, EPOLLIN) < 0) {
		fprintf(stderr, "add container stderr event failed\n");
		return -1;
	}
	exec->ref++;
	return 0;
}

static int hyper_do_exec_cmd(struct hyper_exec *exec, int pipe, struct stdio_config *io)
{
	struct hyper_container *c;

	if (hyper_enter_sandbox(exec->pod, pipe) < 0) {
		perror("enter pidns of pod init failed");
		goto out;
	}

	c = hyper_find_container(exec->pod, exec->container_id);
	if (c == NULL) {
		fprintf(stderr, "can not find container %s\n", exec->container_id);
		goto out;
	}

	if (setns(c->ns, CLONE_NEWNS) < 0) {
		perror("fail to enter container ns");
		goto out;
	}
	if (chdir("/") < 0) {
		perror("fail to change to the root of the rootfs");
		goto out;
	}

	// Make sure we start with a clean environment
	clearenv();

	// set early env. the container env config can overwrite it
	setenv("HOME", "/root", 1);
	setenv("HOSTNAME", exec->pod->hostname, 1);
	if (exec->tty)
		setenv("TERM", "xterm", 1);
	else
		unsetenv("TERM");

	hyper_exec_process(exec, pipe, io);
out:
	hyper_send_type(pipe, -1);
	_exit(125);
}

// do the exec, no return
static void hyper_exec_process(struct hyper_exec *exec, int pipe, struct stdio_config *io)
{
	bool defaultPath = false;
	if (sigprocmask(SIG_SETMASK, &orig_mask, NULL) < 0) {
		perror("sigprocmask restore mask failed");
		goto exit;
	}

	if (exec->workdir && chdir(exec->workdir) < 0) {
		perror("change work directory failed");
		goto exit;
	}

	if (hyper_setup_exec_user(exec) < 0) {
		fprintf(stderr, "setup exec user failed\n");
		goto exit;
	}

	// set the process env
	defaultPath = (exec->argv[0][0] != '/') && (strcmp(exec->container_id, HYPERSTART_EXEC_CONTAINER) != 0);
	if (hyper_setup_env(exec->envs, exec->envs_num, defaultPath) < 0) {
		fprintf(stderr, "setup env failed\n");
		goto exit;
	}

	setsid();

	//send success notification before stdio was installed, otherwise the debug log in hyper_send_type() will be sent to user tty.
	hyper_send_type(pipe, 0);

	if (hyper_install_process_stdio(exec, io) < 0) {
		fprintf(stderr, "dup pts to exec stdio failed\n");
		goto exit_nosend;
	}

	if (execvp(exec->argv[0], exec->argv) < 0) {
		// perror possibly changes the errno.
		int err = errno;
		perror("exec failed");
		 /* the exit codes follow the `chroot` standard,
		    see docker/docs/reference/run.md#exit-status */
		if (err == ENOENT)
			_exit(127);
		else if (err == EACCES)
			_exit(126);
	}

exit:
	hyper_send_type(pipe, -1);
exit_nosend:
	fflush(NULL);
	_exit(125);
}

static void hyper_free_exec(struct hyper_exec *exec)
{
	hyper_cleanup_exec(exec);
	free(exec);
}

int hyper_exec_cmd(struct hyper_pod *pod, char *json, int length)
{
	struct hyper_exec *exec;

	fprintf(stdout, "call hyper_exec_cmd, json %s, len %d\n", json, length);

	exec = hyper_parse_execcmd(json, length);
	if (exec == NULL) {
		fprintf(stderr, "parse exec cmd failed\n");
		return -1;
	}

	if (!hyper_has_container(pod, exec->container_id)) {
		fprintf(stderr, "call hyper_exec_cmd, no such container: %s\n", exec->container_id);
		hyper_free_exec(exec);
		return -1;
	}
	if (hyper_find_exec_by_name(pod, exec->id) != NULL) {
		fprintf(stderr, "call hyper_exec_cmd, process id conflicts");
		hyper_free_exec(exec);
		return -1;
	}

	exec->pod = pod;
	int ret = hyper_run_process(exec);
	if (ret < 0) {
		hyper_free_exec(exec);
	}
	return ret;
}

int hyper_run_process(struct hyper_exec *exec)
{
	int pipe[2] = {-1, -1};
	int pid, ret = -1;
	uint32_t cpid, type;
	struct stdio_config io = {-1, -1,-1, -1,-1, -1};

	if (exec->argv == NULL || exec->seq == 0 || exec->container_id == NULL || strlen(exec->container_id) == 0) {
		fprintf(stderr, "cmd is %p, seq %" PRIu64 ", container %s\n",
			exec->argv, exec->seq, exec->container_id);
		goto out;
	}

	if (hyper_setup_stdio(exec, &io) < 0) {
		fprintf(stderr, "setup exec tty failed\n");
		goto out;
	}

	if (pipe2(pipe, O_CLOEXEC) < 0) {
		perror("create pipe between pod init execcmd failed");
		goto close_tty;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork prerequisite process failed");
		goto close_tty;
	} else if (pid == 0) {
		if (strcmp(exec->container_id, HYPERSTART_EXEC_CONTAINER) == 0) {
			hyper_send_type(pipe[1], getpid());
			hyper_exec_process(exec, pipe[1], &io);
			_exit(125);
		}
		hyper_do_exec_cmd(exec, pipe[1], &io);
	}
	fprintf(stdout, "prerequisite process pid %d\n", pid);

	if (hyper_get_type(pipe[0], &cpid) < 0 || (int)cpid < 0) {
		fprintf(stderr, "run process failed\n");
		goto close_tty;
	}

	if (hyper_setup_stdio_events(exec, &io) < 0) {
		fprintf(stderr, "add pts master event failed\n");
		goto close_tty;
	}

	if (hyper_get_type(pipe[0], &type) < 0 || (int)type < 0) {
		fprintf(stderr, "container process %u exec failed\n", cpid);
		goto close_tty;
	}

	//two message may come back in reversed sequence
	exec->pid = (type == 0) ? cpid : type;
	list_add_tail(&exec->list, &exec->pod->exec_head);
	exec->ref++;
	fprintf(stdout, "%s process pid %d\n", __func__, exec->pid);
	ret = 0;
out:
	close(io.stdinfd);
	close(io.stdoutfd);
	close(io.stderrfd);
	close(pipe[0]);
	close(pipe[1]);
	return ret;
close_tty:
	hyper_reset_event(&exec->stdinev);
	hyper_reset_event(&exec->stdoutev);
	hyper_reset_event(&exec->stderrev);
	list_del_init(&exec->list);

	close(exec->ptyfd);
	close(io.stdinevfd);
	close(io.stdoutevfd);
	close(io.stderrevfd);
	goto out;
}

static int hyper_release_exec(struct hyper_exec *exec)
{
	if (--exec->ref != 0) {
		fprintf(stdout, "still have %d user of exec\n", exec->ref);
		return 0;
	}

	/* exec has no pty or the pty user already exited */
	fprintf(stdout, "last user of exec exit, release\n");

	hyper_reset_event(&exec->stdinev);
	hyper_reset_event(&exec->stdoutev);
	hyper_reset_event(&exec->stderrev);

	list_del_init(&exec->list);

	hyper_send_exec_eof(exec);

	hyper_send_exec_code(exec);

	fprintf(stdout, "%s exit code %" PRIu8"\n", __func__, exec->code);
	if (exec->init) {
		fprintf(stdout, "%s container init exited %s, remains %d\n",
			__func__, exec->pod->req_destroy?"manually":"automatically", exec->pod->remains);

		if (--exec->pod->remains == 0 && exec->pod->req_destroy) {
			/* shutdown vm manually, hyper doesn't care the pod finished codes */
			hyper_pod_destroyed(exec->pod, 0);
		}

		return 0;
	}

	hyper_free_exec(exec);
	return 0;
}

struct hyper_exec *hyper_find_process(struct hyper_pod *pod, const char *container, const char *process)
{
	struct hyper_container *c = hyper_find_container(pod, container);
	if (c) {
		if (strcmp(c->exec.id, process) == 0) {
			return &c->exec;
		}
	} else {
		return NULL;
	}

	struct hyper_exec *exec = hyper_find_exec_by_name(pod, process);
	if (exec) {
		if (strcmp(exec->container_id, container) == 0) {
			return exec;
		}
	}

	return NULL;
}

struct hyper_exec *hyper_find_exec_by_name(struct hyper_pod *pod, const char *process)
{
	struct hyper_exec *exec;

	list_for_each_entry(exec, &pod->exec_head, list) {
		if (strcmp(exec->id, process) == 0) {
			return exec;
		}
	}

	return NULL;
}

struct hyper_exec *hyper_find_exec_by_pid(struct list_head *head, int pid)
{
	struct hyper_exec *exec;

	list_for_each_entry(exec, head, list) {
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
		if (exec->seq != seq)
			continue;

		return exec;
	}

	return NULL;
}

static int hyper_kill_container_processes(struct hyper_container *c) {
	struct stat st;
	int pid, loop = 1;
	DIR *dp;
	struct dirent *de;

	if (fstat(c->ns, &st) < 0) {
		perror("fail to stat mnt ns");
		return -1;
	}

	fprintf(stdout, "container init process %d\n", c->exec.pid);
	while (loop) {
		loop = 0;

		dp = opendir("/proc");
		if (dp == NULL) {
			perror("open /proc failed");
			return -1;
		}

		while ((de = readdir(dp)) && de != NULL) {
			char mntns[512];
			struct stat st1;

			if (!isdigit(de->d_name[0]))
				continue;
			pid = atoi(de->d_name);
			if (pid == 1 || pid == c->exec.pid)
				continue;

			sprintf(mntns, "/proc/%d/ns/mnt", pid);

			if (stat(mntns, &st1) < 0) {
				fprintf(stdout, "fail to stat mnt ns of process %d: %s\n",
					pid, strerror(errno));
				continue;
			}

			if (st.st_ino != st1.st_ino)
			       continue;

			kill(pid, SIGKILL);
			loop = 1;
		}

		closedir(dp);
	}
	return 0;
}

int hyper_handle_exec_exit(struct hyper_pod *pod, int pid, uint8_t code)
{
	struct hyper_exec *exec;

	exec = hyper_find_exec_by_pid(&pod->exec_head, pid);
	if (exec == NULL) {
		return 0;
	}

	fprintf(stdout, "%s exec exit pid %d, seq %" PRIu64 ", container %s\n",
		__func__, exec->pid, exec->seq, exec->container_id);

	exec->code = code;
	exec->exit = 1;

	close(exec->ptyfd);
	exec->ptyfd = -1;

	if (exec->init)
		hyper_kill_container_processes(container_of(exec, struct hyper_container, exec));

	hyper_release_exec(exec);

	return 0;
}
