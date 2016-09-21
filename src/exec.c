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

static int hyper_release_exec(struct hyper_exec *, struct hyper_pod *);
static void hyper_exec_process(struct hyper_exec *exec);

static int send_exec_finishing(uint64_t seq, int len, int code, int block)
{
	struct hyper_buf *buf = &ctl.tty.wbuf;

	if (buf->get + len > buf->size) {
		uint8_t *data;
		fprintf(stdout, "%s: tty buf full\n", __func__);

		data = realloc(buf->data, buf->size + len);
		if (data == NULL) {
			perror("realloc failed");
			return -1;
		}
		buf->data = data;
		buf->size += len;
	}

	/* no in event, no more data, send eof */
	hyper_set_be64(buf->data + buf->get, seq);
	hyper_set_be32(buf->data + buf->get + 8, len);
	if (len > 12)
		buf->data[buf->get + 12] = code;

	buf->get += len;
	if (!block) {
		hyper_modify_event(ctl.efd, &ctl.tty, EPOLLIN | EPOLLOUT);
		return 0;
	}

	if (hyper_setfd_block(ctl.tty.fd) < 0 ||
	    hyper_send_data(ctl.tty.fd, buf->data, buf->get) < 0 ||
	    hyper_setfd_nonblock(ctl.tty.fd) < 0) {
		fprintf(stderr, "send eof failed\n");
		return -1;
	}

	return 0;
}

static int hyper_send_exec_eof(struct hyper_exec *exec, int block) {
	return send_exec_finishing(exec->seq, 12, -1, block);
}

static int hyper_send_exec_code(struct hyper_exec *exec, int block) {
	return send_exec_finishing(exec->seq, 13, exec->code, block);
}

static void pts_hup(struct hyper_event *de, int efd, struct hyper_exec *exec)
{
	struct hyper_pod *pod = de->ptr;

	fprintf(stdout, "%s, seq %" PRIu64"\n", __func__, exec->seq);

	hyper_event_hup(de, efd);

	hyper_release_exec(exec, pod);
}

static void stdin_hup(struct hyper_event *de, int efd)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stdinev);
	fprintf(stdout, "%s\n", __func__);
	return pts_hup(de, efd, exec);
}

static void stdout_hup(struct hyper_event *de, int efd)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stdoutev);
	fprintf(stdout, "%s\n", __func__);
	return pts_hup(de, efd, exec);
}

static void stderr_hup(struct hyper_event *de, int efd)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stderrev);
	fprintf(stdout, "%s\n", __func__);
	return pts_hup(de, efd, exec);
}

static int pts_loop(struct hyper_event *de, uint64_t seq, int efd, struct hyper_exec *exec)
{
	int size = -1;
	int flag = de->flag | EPOLLOUT;
	struct hyper_buf *buf = &ctl.tty.wbuf;

	if (FULL(buf)) {
		flag |= EPOLLPRI;
		goto out;
	}

	do {
		size = read(de->fd, buf->data + buf->get + 12, buf->size - buf->get - 12);
		fprintf(stdout, "%s: read %d data\n", __func__, size);
		if (size < 0) {
			if (errno == EINTR)
				continue;

			if (errno != EAGAIN && errno != EIO) {
				perror("fail to read tty fd");
				return -1;
			}

			break;
		}
		if (size == 0) { // eof
			pts_hup(de, efd, exec);
			return 0;
		}

		hyper_set_be64(buf->data + buf->get, seq);
		hyper_set_be32(buf->data + buf->get + 8, size + 12);
		buf->get += size + 12;
	} while (!FULL(buf));

	if (FULL(buf)) {
		flag |= EPOLLPRI;
		/* del & add event to move event to tail, this gives
		 * other event a chance to write data to wbuf of tty. */
		hyper_requeue_event(ctl.efd, de);
	}
out:
	if (hyper_modify_event(ctl.efd, &ctl.tty, flag) < 0) {
		fprintf(stderr, "modify ctl tty event to %d failed\n", flag);
		return -1;
	}

	return 0;
}

static int write_to_stdin(struct hyper_event *de, int efd)
{
	struct hyper_exec *exec = container_of(de, struct hyper_exec, stdinev);
	fprintf(stdout, "%s, seq %" PRIu64"\n", __func__, exec->seq);

	int ret = hyper_event_write(de, efd);

	if (ret >= 0 && de->wbuf.get == 0 && exec->close_stdin_request)
		pts_hup(de, efd, exec);

	return ret;
}

struct hyper_event_ops in_ops = {
	.hup		= stdin_hup,
	.write		= write_to_stdin,
	.wbuf_size	= 512,
};

static int stdout_loop(struct hyper_event *de, int efd)
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

static int stderr_loop(struct hyper_event *de, int efd)
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

	// check the config
	if (!user) {
		if (group || exec->nr_additional_groups > 0) {
			fprintf(stderr, "group or additional groups can only be set when user is set\n");
			return -1;
		}
		return 0;
	}

	// get uid
	fprintf(stdout, "try to find the user: %s\n", user);
	struct passwd *pwd = hyper_getpwnam(user);
	if (pwd == NULL) {
		perror("can't find the user");
		return -1;
	}
	uid_t uid = pwd->pw_uid;

	// get gid
	gid_t gid = pwd->pw_gid;
	if (group) {
		fprintf(stdout, "try to find the group: %s\n", group);
		struct group *gr = hyper_getgrnam(group);
		if (gr == NULL) {
			perror("can't find the group");
			return -1;
		}
		gid = gr->gr_gid;
	}

	// get all gids
	int i, ngroups = 10;
	gid_t *reallocgroups, *groups = malloc(sizeof(gid_t) * ngroups);
	if (groups == NULL)
		goto fail;
	if (hyper_getgrouplist(pwd->pw_name, gid, groups, &ngroups) < 0) {
		reallocgroups = realloc(groups, sizeof(gid_t) * ngroups);
		if (reallocgroups == NULL)
			goto fail;
		groups = reallocgroups;
		if (hyper_getgrouplist(pwd->pw_name, gid, groups, &ngroups) < 0)
			goto fail;
	}
	reallocgroups = realloc(groups, sizeof(gid_t) * (ngroups + exec->nr_additional_groups));
	if (reallocgroups == NULL)
		goto fail;
	groups = reallocgroups;
	for (i = 0; i < exec->nr_additional_groups; i++) {
		fprintf(stdout, "try to find the group: %s\n", exec->additional_groups[i]);
		struct group *gr = hyper_getgrnam(exec->additional_groups[i]);
		if (gr == NULL) {
			perror("can't find the group");
			goto fail;
		}
		groups[ngroups] = gr->gr_gid;
		ngroups++;
	}

	// setup the owner of tty
	if (exec->tty) {
		char ptmx[512];
		sprintf(ptmx, "/dev/pts/%d", exec->ptyno);
		chown(ptmx, uid, gid);
	}

	// apply
	if (setgroups(ngroups, groups) < 0) {
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

	// set user related envs. the container env config can overwrite it
	setenv("USER", pwd->pw_name, 1);
	setenv("HOME", pwd->pw_dir, 1);

	return 0;

fail:
	free(groups);
	return -1;
}

static int hyper_setup_exec_notty(struct hyper_exec *e)
{
	if (e->errseq == 0)
		return -1;

	int inpipe[2];
	if (pipe2(inpipe, O_CLOEXEC) < 0) {
		fprintf(stderr, "creating stderr pipe failed\n");
		return -1;
	}
	hyper_setfd_nonblock(inpipe[1]);
	e->stdinev.fd = inpipe[1];
	e->stdinfd = inpipe[0];

	int outpipe[2];
	if (pipe2(outpipe, O_CLOEXEC) < 0) {
		fprintf(stderr, "creating stderr pipe failed\n");
		return -1;
	}
	hyper_setfd_nonblock(outpipe[0]);
	e->stdoutev.fd = outpipe[0];
	e->stdoutfd = outpipe[1];

	int errpipe[2];
	if (pipe2(errpipe, O_CLOEXEC) < 0) {
		fprintf(stderr, "creating stderr pipe failed\n");
		return -1;
	}
	hyper_setfd_nonblock(errpipe[0]);
	e->stderrev.fd = errpipe[0];
	e->stderrfd = errpipe[1];

	return 0;
}

static int hyper_setup_exec_tty(struct hyper_exec *e)
{
	int unlock = 0;
	int ptymaster;
	char ptmx[512], path[512];

	if (e->seq == 0) {
		fprintf(stderr, "e->seq should be set\n");
		return -1;
	}

	if (!e->tty) { // don't use tty for stdio
		return hyper_setup_exec_notty(e);
	}

	if (e->errseq > 0) {
		int errpipe[2];
		if (pipe2(errpipe, O_CLOEXEC) < 0) {
			fprintf(stderr, "creating stderr pipe failed\n");
			return -1;
		}
		hyper_setfd_nonblock(errpipe[0]);
		e->stderrev.fd = errpipe[0];
		e->stderrfd = errpipe[1];
	}

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

	ptymaster = open(ptmx, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
	if (ptymaster < 0) {
		perror("open ptmx device for execcmd failed");
		return -1;
	}

	if (ioctl(ptymaster, TIOCSPTLCK, &unlock) < 0) {
		perror("ioctl unlock ptmx device failed");
		return -1;
	}

	if (ioctl(ptymaster, TIOCGPTN, &e->ptyno) < 0) {
		perror("ioctl get execcmd pty device failed");
		return -1;
	}

	if (sprintf(ptmx, "%s/%d", path, e->ptyno) < 0) {
		fprintf(stderr, "get ptmx path failed\n");
		return -1;
	}

	e->ptyfd = open(ptmx, O_RDWR | O_NOCTTY | O_CLOEXEC);
	fprintf(stdout, "get pty device for exec %s\n", ptmx);

	e->stdinev.fd = ptymaster;
	e->stdoutev.fd = dup(ptymaster);
	if (e->errseq == 0) {
		e->stderrev.fd = dup(e->stdoutev.fd);
	}
	fprintf(stdout, "%s pts event %p, fd %d %d\n",
		__func__, &e->stdinev, ptymaster, e->ptyfd);
	return 0;
}

static int hyper_dup_exec_tty(struct hyper_exec *e)
{
	int ret = -1;

	fprintf(stdout, "%s\n", __func__);
	setsid();

	if (e->tty) {
		char ptmx[512];
		sprintf(ptmx, "/dev/pts/%d", e->ptyno);
		// reopen slave ptyfd for correcting the symlink path of the /dev/fd/1
		e->ptyfd = open(ptmx, O_RDWR | O_CLOEXEC);
		if (e->ptyfd < 0 || ioctl(e->ptyfd, TIOCSCTTY, NULL) < 0) {
			perror("ioctl pty device for execcmd failed");
			goto out;
		}
		e->stdinfd = e->ptyfd;
		e->stdoutfd = e->ptyfd;
		if (e->errseq == 0)
			e->stderrfd = e->ptyfd;
		close(e->stdinev.fd);
		close(e->stdoutev.fd);
		close(e->stderrev.fd);
	}

	fflush(stdout);

	if (dup2(e->stdinfd, STDIN_FILENO) < 0) {
		perror("dup tty device to stdin failed");
		goto out;
	}

	if (dup2(e->stdoutfd, STDOUT_FILENO) < 0) {
		perror("dup tty device to stdout failed");
		goto out;
	}

	if (dup2(e->stderrfd, STDERR_FILENO) < 0) {
		perror("dup err pipe to stderr failed");
		goto out;
	}

	ret = 0;
out:
	return ret;
}

static int hyper_watch_exec_pty(struct hyper_exec *exec, struct hyper_pod *pod)
{
	fprintf(stdout, "hyper_init_event container pts event %p, ops %p, fd %d\n",
		&exec->stdinev, &in_ops, exec->stdinev.fd);

	if (exec->seq == 0)
		return 0;

	if (hyper_init_event(&exec->stdinev, &in_ops, pod) < 0 ||
	    hyper_add_event(ctl.efd, &exec->stdinev, EPOLLOUT) < 0) {
		fprintf(stderr, "add container stdin event failed\n");
		return -1;
	}
	exec->ref++;

	if (hyper_init_event(&exec->stdoutev, &out_ops, pod) < 0 ||
	    hyper_add_event(ctl.efd, &exec->stdoutev, EPOLLIN) < 0) {
		fprintf(stderr, "add container stdout event failed\n");
		return -1;
	}
	exec->ref++;

	if (hyper_init_event(&exec->stderrev, &err_ops, pod) < 0 ||
	    hyper_add_event(ctl.efd, &exec->stderrev, EPOLLIN) < 0) {
		fprintf(stderr, "add container stderr event failed\n");
		return -1;
	}
	exec->ref++;
	return 0;
}

static int hyper_do_exec_cmd(struct hyper_exec *exec, struct hyper_pod *pod, int pipe)
{
	struct hyper_container *c;

	if (hyper_enter_sandbox(pod, pipe) < 0) {
		perror("enter pidns of pod init failed");
		hyper_send_type(pipe, -1);
		goto out;
	}

	c = hyper_find_container(pod, exec->id);
	if (c == NULL) {
		fprintf(stderr, "can not find container %s\n", exec->id);
		goto out;
	}

	if (setns(c->ns, CLONE_NEWNS) < 0) {
		perror("fail to enter container ns");
		goto out;
	}
	chdir("/");

	/* TODO: merge container env to exec env in hyperd */
	if (hyper_setup_env(c->exec.envs, c->exec.envs_num) < 0) {
		fprintf(stderr, "setup container envs for exec failed\n");
		goto out;
	}

	// set early env. the container env config can overwrite it
	setenv("HOME", "/root", 1);
	setenv("HOSTNAME", pod->hostname, 1);
	if (exec->tty)
		setenv("TERM", "xterm", 1);
	else
		unsetenv("TERM");

	hyper_exec_process(exec);

out:
	_exit(125);
}

// do the exec, no return
static void hyper_exec_process(struct hyper_exec *exec)
{
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
	if (hyper_setup_env(exec->envs, exec->envs_num) < 0) {
		fprintf(stderr, "setup env failed\n");
		goto exit;
	}

	if (hyper_dup_exec_tty(exec) < 0) {
		fprintf(stderr, "dup pts to exec stdio failed\n");
		goto exit;
	}

	if (execvp(exec->argv[0], exec->argv) < 0) {
		perror("exec failed");

		 /* the exit codes follow the `chroot` standard,
		    see docker/docs/reference/run.md#exit-status */
		if (errno == ENOENT)
			_exit(127);
		else if (errno == EACCES)
			_exit(126);
	}

exit:
	fflush(stdout);
	_exit(125);
}

static void hyper_free_exec(struct hyper_exec *exec)
{
	int i;

	free(exec->id);

	for (i = 0; i < exec->argc; i++) {
		//fprintf(stdout, "argv %d %s\n", i, exec->argv[i]);
		free(exec->argv[i]);
	}

	free(exec->argv);
	free(exec);
}

int hyper_exec_cmd(char *json, int length)
{
	struct hyper_exec *exec;

	fprintf(stdout, "call hyper_exec_cmd, json %s, len %d\n", json, length);

	exec = hyper_parse_execcmd(json, length);
	if (exec == NULL) {
		fprintf(stderr, "parse exec cmd failed\n");
		return -1;
	}

	int ret = hyper_run_process(exec);
	if (ret < 0) {
		hyper_free_exec(exec);
	}
	return ret;
}

int hyper_run_process(struct hyper_exec *exec)
{
	struct hyper_pod *pod = &global_pod;
	int pipe[2] = {-1, -1};
	int pid, ret = -1;
	uint32_t type;

	if (exec->argv == NULL) {
		fprintf(stderr, "cmd is %p, seq %" PRIu64 ", container %s\n",
			exec->argv, exec->seq, exec->id);
		goto out;
	}

	if (hyper_setup_exec_tty(exec) < 0) {
		fprintf(stderr, "setup exec tty failed\n");
		goto out;
	}

	if (hyper_watch_exec_pty(exec, pod) < 0) {
		fprintf(stderr, "add pts master event failed\n");
		goto close_tty;
	}

	list_add_tail(&exec->list, &pod->exec_head);
	exec->ref++;

	if (pipe2(pipe, O_CLOEXEC) < 0) {
		perror("create pipe between pod init execcmd failed");
		goto close_tty;
	}

	pid = fork();
	if (pid < 0) {
		perror("clone hyper_do_exec_cmd failed");
		goto close_tty;
	} else if (pid == 0) {
		hyper_do_exec_cmd(exec, pod, pipe[1]);
	}
	fprintf(stdout, "do_exec_cmd pid %d\n", pid);

	if (hyper_get_type(pipe[0], &type) < 0 || (int)type < 0) {
		fprintf(stderr, "hyper init doesn't get execcmd ready message\n");
		goto close_tty;
	}
	exec->pid = type;

	fprintf(stdout, "%s get ready message %"PRIu32 "\n", __func__, type);
	ret = 0;
out:
	close(pipe[0]);
	close(pipe[1]);
	return ret;
close_tty:
	hyper_reset_event(&exec->stdinev);
	hyper_reset_event(&exec->stdoutev);
	hyper_reset_event(&exec->stderrev);
	list_del_init(&exec->list);

	close(exec->ptyfd);
	close(exec->stdinfd);
	close(exec->stdoutfd);
	close(exec->stderrfd);
	goto out;
}

static int hyper_send_pod_finished(struct hyper_pod *pod)
{
	int ret = -1;
	struct hyper_container *c;
	uint8_t *data = NULL, *new;
	int c_num = 0;

	list_for_each_entry(c, &pod->containers, list) {
		c_num++;
		new = realloc(data, c_num * 4);
		if (new == NULL)
			goto out;

		hyper_set_be32(new + ((c_num - 1) * 4), c->exec.code);
		data = new;
	}

	ret = hyper_send_msg_block(ctl.chan.fd, PODFINISHED, c_num * 4, data);
out:
	free(data);
	return ret;
}

static int hyper_release_exec(struct hyper_exec *exec,
			      struct hyper_pod *pod)
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

	hyper_send_exec_eof(exec, 0);

	hyper_send_exec_code(exec, 0);

	fprintf(stdout, "%s exit code %" PRIu8"\n", __func__, exec->code);
	if (exec->init) {
		fprintf(stdout, "%s container init exited %s, remains %d\n",
			__func__, pod->req_destroy?"manually":"automatically", pod->remains);

		// TODO send finish of this container and full cleanup
		if (--pod->remains > 0)
			return 0;

		if (pod->req_destroy) {
			/* shutdown vm manually, hyper doesn't care the pod finished codes */
			hyper_pod_destroyed(0);
		} else {
			/* send out pod finish message, hyper will decide if restart pod or not */
			hyper_send_pod_finished(pod);
		}

		hyper_cleanup_pod(pod);
		return 0;
	}

	hyper_free_exec(exec);
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

			fprintf(stdout, "kill process of container %d\n", pid);
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
		fprintf(stdout, "can not find exec whose pid is %d\n",
			pid);
		return 0;
	}

	fprintf(stdout, "%s exec exit pid %d, seq %" PRIu64 ", container %s\n",
		__func__, exec->pid, exec->seq, exec->id);

	exec->code = code;
	exec->exit = 1;

	close(exec->ptyfd);
	exec->ptyfd = -1;
	close(exec->stdinfd);
	exec->stdinfd = -1;
	close(exec->stdoutfd);
	exec->stdoutfd = -1;
	close(exec->stderrfd);
	exec->stderrfd = -1;

	hyper_release_exec(exec, pod);

	if (exec->init)
		hyper_kill_container_processes(container_of(exec, struct hyper_container, exec));

	return 0;
}

void hyper_cleanup_exec(struct hyper_pod *pod)
{
	struct hyper_exec *exec, *next;

	list_for_each_entry_safe(exec, next, &pod->exec_head, list) {
		fprintf(stdout, "send eof for exec seq %" PRIu64 "\n", exec->seq);
		if (hyper_send_exec_eof(exec, 1) < 0 ||
		    hyper_send_exec_code(exec, 1) < 0)
			fprintf(stderr, "send eof failed\n");
	}
}
