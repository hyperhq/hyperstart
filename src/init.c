#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <mntent.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <inttypes.h>
#include <ctype.h>

#include "../config.h"
#include "hyper.h"
#include "net.h"
#include "util.h"
#include "exec.h"
#include "event.h"
#include "parse.h"
#include "container.h"

struct hyper_pod global_pod = {
	.ce_head	=	LIST_HEAD_INIT(global_pod.ce_head),
	.pe_head	=	LIST_HEAD_INIT(global_pod.pe_head),
};
struct hyper_exec *global_exec;

#define MAXEVENTS	10

struct hyper_ctl ctl;

static void hyper_cleanup_pod(struct hyper_pod *pod);
static int hyper_handle_exit(struct hyper_pod *pod, int to,
			   int container, int option);

static int hyper_set_win_size(char *json, int length)
{
	struct hyper_win_size ws = {
		.tty = NULL,
	};
	struct winsize size;
	struct hyper_exec *exec;
	char *name, path[128];
	int fd, ret;

	fprintf(stdout, "call hyper_win_size, json %s, len %d\n", json, length);
	if (hyper_parse_winsize(&ws, json, length) < 0) {
		fprintf(stderr, "set term size failed\n");
		return -1;
	}

	name = ws.tty;
	if (!ws.tty) {
		exec = hyper_find_exec_by_seq(&global_pod, ws.seq);
		if (exec == NULL) {
			fprintf(stdout, "can not find exec whose seq is %" PRIu64"\n", ws.seq);
			return 0;
		}

		fprintf(stdout, "find exec %s, pts %s, pid is %d, seq is %" PRIu64"\n",
			exec->id ? exec->id : "pod", exec->pty, exec->pid, ws.seq);
		name = exec->pty;
	} else {
		if (sprintf(path, "/dev/%s", ws.tty) < 0) {
			fprintf(stderr, "get tty device failed\n");
			return -1;
		}
		name = path;
	}

	fprintf(stdout, "try to open %s\n", name);
	ret = hyper_open_serial_dev(name);
	if (ret < 0) {
		fprintf(stderr, "cannot open %s to set term size\n", name);
		goto out;
	}

	size.ws_row = ws.row;
	size.ws_col = ws.column;
	fd = ret;

	ret = ioctl(fd, TIOCSWINSZ, &size);
	if (ret < 0)
		fprintf(stderr, "cannot ioctl to set %s term size\n", name);

	close(fd);
out:
	free(ws.tty);
	return ret;
}

static int pod_ctl_pipe_handle(struct hyper_event *de, uint32_t len)
{
	struct hyper_buf *buf = &de->rbuf;
	struct hyper_pod *pod = de->ptr;
	uint32_t type;

	fprintf(stdout, "%s\n", __func__);

	type = hyper_get_be32(buf->data);

	switch (type) {
	case STOPPOD:
		fprintf(stdout, "get type STOPPOD, exit\n");
		hyper_cleanup_pod(pod);
	case RESTARTCONTAINER:
		fprintf(stdout, "%s get type RESTARTCONTAINER\n", __func__);
		if (hyper_restart_containers(pod) < 0)
			return -1;
		break;
	case EXECCMD:
		if (hyper_container_execcmd(pod) < 0)
			return -1;
		break;
	default:
		break;
	}

	return 0;
}

static int hyper_handle_exit(struct hyper_pod *pod, int to,
			   int container, int option)
{
	int pid, status;
	/* pid + exit code */
	uint8_t data[5];

	while ((pid = waitpid(-1, &status, option)) > 0) {
		data[4] = 0;

		if (WIFEXITED(status)) {
			data[4] = WEXITSTATUS(status);
			fprintf(stdout, "pid %d exit normally, status %" PRIu8 "\n",
				pid, data[4]);

		} else if (WIFSIGNALED(status)) {
			fprintf(stdout, "pid %d exit by signal, status %d\n",
				pid, WTERMSIG(status));
		}

		if (container) {
			hyper_set_be32(data, pid);
			if (hyper_send_msg(to, FINISHCMD, 5, data) < 0) {
				fprintf(stderr, "pod signal_loop send finishcmd failed\n");
				return -1;
			}

			continue;
		}

		if (hyper_send_exec_eof(to, pod, &pod->pe_head, pid, data[4]) < 0)
			fprintf(stderr, "signal_loop send eof failed\n");
	}

	if (option == WNOHANG)
		return 0;

	/* send ack message to hyper init. */
	if (hyper_send_type(to, ACK) < 0) {
		fprintf(stderr, "send ACK of STOPPOD to hyper init failed\n");
		return -1;
	}

	return 0;
}

static int signal_loop(struct hyper_event *de, int container)
{
	int size, to;
	struct signalfd_siginfo sinfo;
	struct hyper_pod *pod = de->ptr;

	if (container)
		to = pod->ctl.fd;
	else
		to = ctl.tty.fd;

	fprintf(stdout, "%s write to %d\n", __func__, to);

	while (1) {
		size = read(de->fd, &sinfo, sizeof(struct signalfd_siginfo));
		if (size <= 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;

			perror("fail to read signal fd");
			return -1;
		} else if (size != sizeof(struct signalfd_siginfo)) {
			perror("read signalfd siginfo failed");
			return -1;
		}

		if (sinfo.ssi_signo != SIGCHLD) {
			fprintf(stderr, "why give me signal %d?\n", sinfo.ssi_signo);
			return 0;
		}

		hyper_handle_exit(pod, to, container, WNOHANG);
	}

	return 0;
}

static int pod_signal_loop(struct hyper_event *de)
{
	return signal_loop(de, 1);
}

static int hyper_signal_loop(struct hyper_event *de)
{
	return signal_loop(de, 0);
}

static struct hyper_event_ops pod_ctl_pipe_ops = {
	.read		= hyper_event_read,
	.handle		= pod_ctl_pipe_handle,
	.hup		= hyper_event_hup,
	.rbuf_size	= 8,
	.len_offset	= 4,
};

static struct hyper_event_ops pod_signal_ops = {
	.read		= pod_signal_loop,
	.hup		= hyper_event_hup,
};

static int pod_init_loop(struct hyper_pod *pod)
{
	int i, n;
	struct epoll_event *events;

	pod->efd = epoll_create1(EPOLL_CLOEXEC);
	if (pod->efd < 0) {
		perror("epoll_create failed");
		return -1;
	}

	fprintf(stdout, "hyper_init_event pod ctl pipe event %p, ops %p, fd %d\n",
		&pod->ctl, &pod_ctl_pipe_ops, pod->ctl.fd);
	if (hyper_init_event(&pod->ctl, &pod_ctl_pipe_ops, pod) < 0 ||
	    hyper_add_event(pod->efd, &pod->ctl, EPOLLIN) < 0) {
		fprintf(stderr, "hyper add pod ctl pipe event failed\n");
		return -1;
	}

	fprintf(stdout, "hyper_init_event pod signal event %p, ops %p, fd %d\n",
		&pod->sig, &pod_signal_ops, pod->sig.fd);
	if (hyper_init_event(&pod->sig, &pod_signal_ops, pod) < 0 ||
	    hyper_add_event(pod->efd, &pod->sig, EPOLLIN) < 0) {
		fprintf(stderr, "hyper add pod tty pipe event failed\n");
		return -1;
	}

	events = calloc(MAXEVENTS, sizeof(*events));

	while (1) {
		n = epoll_wait(pod->efd, events, MAXEVENTS, -1);
		fprintf(stdout, "%s epoll_wait %d\n", __func__, n);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("pod wait event failed");
			return -1;
		}

		for (i = 0; i < n; i++) {
			if (hyper_handle_event(pod->efd, &events[i]) < 0)
				return -1;
		}
	}

	close(pod->efd);
	return 0;
}

struct hyper_pod_arg {
	struct hyper_pod	*pod;
	int		ctl_pipe[2];
};

static int hyper_pod_init(void *data)
{
	struct hyper_pod_arg *arg = data;
	struct hyper_pod *pod = arg->pod;
	sigset_t mask;

	close(arg->ctl_pipe[0]);
	close(ctl.sig.fd);
	close(ctl.efd);
	close(ctl.chan.fd);
	close(ctl.tty.fd);

	pod->ctl.fd = arg->ctl_pipe[1];
	if (hyper_setfd_cloexec(pod->ctl.fd) < 0) {
		perror("set pod init ctl pipe fd FD_CLOEXEC failed");
		goto fail;
	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("sigprocmask SIGCHLD failed");
		goto fail;
	}

	pod->sig.fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (pod->sig.fd < 0) {
		perror("create signalfd failed");
		goto fail;
	}

	if (hyper_start_containers(pod) < 0)
		goto fail;

	fprintf(stdout, "pod ctl_pipe %d\n", arg->ctl_pipe[1]);
	if (hyper_send_type(arg->ctl_pipe[1], READY) < 0) {
		fprintf(stderr, "container init send ready message failed\n");
		goto fail;
	}
loop:
	pod_init_loop(pod);
	_exit(-1);

fail:
	hyper_send_type(arg->ctl_pipe[1], ERROR);
	goto loop;
}

static int hyper_ctl_pipe_handle(struct hyper_event *de, uint32_t len)
{
	struct hyper_buf *buf = &de->rbuf;
	struct hyper_pod *pod = de->ptr;
	uint32_t type, pid = 0;
	uint8_t code;

	/* container exec finish message */
	fprintf(stdout, "%s\n", __func__);

	type = hyper_get_be32(buf->data);

	switch (type) {
	case ACK:
		/* ACK only being sent on stoppod, in this case, ctl pipe
		 * fd is block, and ACK is the last message, exit loop. */
		fprintf(stdout, "hyper_ctl_pipe_loop get ack\n");
		return 1;
	case FINISHCMD:
		pid = hyper_get_be32(buf->data + 8);
		code = buf->data[12];
		if (hyper_send_exec_eof(ctl.tty.fd, pod, &pod->ce_head, pid, code) < 0) {
			fprintf(stderr, "hyper_ctl_pipe_loop send eof failed\n");
			return -1;
		}
		break;
	default:
		fprintf(stdout, "get unknown type %" PRIu32"\n", type);
		break;
	}

	return 0;
}

static int hyper_setup_pty(struct hyper_pod *pod)
{
	int i;
	char root[512];
	struct hyper_container *c;

	for (i = 0; i < pod->c_num; i++) {
		c = &pod->c[i];

		sprintf(root, "/tmp/hyper/%s/devpts/", c->id);

		if (hyper_mkdir(root) < 0) {
			perror("make container pts directroy failed");
			return -1;
		}

		if (mount("devpts", root, "devpts", MS_NOSUID,
			  "newinstance,ptmxmode=0666,mode=0620") < 0) {
			perror("mount devpts failed");
			return -1;
		}

		list_add_tail(&c->exec.list, &pod->ce_head);

		if (hyper_setup_exec_tty(&c->exec) < 0) {
			fprintf(stderr, "setup container pts failed\n");
			return -1;
		}
	}

	return 0;
}

static int hyper_watch_pty(struct hyper_pod *pod)
{
	int i;
	struct hyper_container *c;

	for (i = 0; i < pod->c_num; i++) {
		c = &pod->c[i];

		fprintf(stdout, "hyper_init_event container pts event %p, ops %p, fd %d\n",
			&c->exec.e, &pts_ops, c->exec.e.fd);
		if (hyper_init_event(&c->exec.e, &pts_ops, pod) < 0 ||
		    hyper_add_event(ctl.efd, &c->exec.e, EPOLLIN) < 0) {
			fprintf(stderr, "add container pts master event failed\n");
			return -1;
		}
	}

	return 0;
}

static struct hyper_event_ops hyper_ctl_pipe_ops = {
	.read		= hyper_event_read,
	.handle		= hyper_ctl_pipe_handle,
	.hup		= hyper_event_hup,
	.rbuf_size	= 256,
	.len_offset	= 4,
};

static int hyper_setup_container(struct hyper_pod *pod)
{
	int stacksize = getpagesize() * 4;
	int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC |
		    CLONE_NEWUTS | CLONE_VM | SIGCHLD;

	struct hyper_pod_arg arg = {
		.pod		= NULL,
		.ctl_pipe	= {-1, -1},
	};

	uint32_t type;
	void *stack;

	if (hyper_setup_pty(pod) < 0) {
		fprintf(stderr, "setup pty failed\n");
		return -1;
	}

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, arg.ctl_pipe) < 0) {
		perror("create pipe between hyper init and pod init failed");
		return -1;
	}

	stack = malloc(stacksize);
	if (stack == NULL) {
		perror("fail to allocate stack for container init");
		return -1;
	}

	arg.pod = pod;

	pod->init_pid = clone(hyper_pod_init, stack + stacksize, flags, &arg);
	free(stack);
	if (pod->init_pid < 0) {
		perror("create container init process failed");
		return -1;
	}

	close(arg.ctl_pipe[1]);
	ctl.ctl.fd = arg.ctl_pipe[0];
	fprintf(stdout, "pod init pid %d\n", pod->init_pid);

	/* Wait for container start */
	if (hyper_get_type_block(ctl.ctl.fd, &type) < 0) {
		perror("get container init ready message failed");
		return -1;
	}

	if (type != READY) {
		fprintf(stderr, "get incorrect message type %d, expect READY\n", type);
		return -1;
	}

	if (hyper_watch_pty(pod) < 0) {
		fprintf(stderr, "watch pty failed\n");
		return -1;
	}

	if (hyper_setfd_cloexec(ctl.ctl.fd) < 0) {
		perror("set ctl pipe fd FD_CLOEXEC failed");
		return -1;
	}

	fprintf(stdout, "hyper_init_event hyper ctl pipe fd %d\n", ctl.ctl.fd);
	if (hyper_init_event(&ctl.ctl, &hyper_ctl_pipe_ops, pod) < 0 ||
	    hyper_add_event(ctl.efd, &ctl.ctl, EPOLLIN) < 0) {
		return -1;
	}

	return 0;
}

#ifdef WITH_VBOX

#define MAX_HOST_NAME  256
#define MAX_NLS_NAME    32

#define VBSF_MOUNT_SIGNATURE_BYTE_0 '\377'
#define VBSF_MOUNT_SIGNATURE_BYTE_1 '\376'
#define VBSF_MOUNT_SIGNATURE_BYTE_2 '\375'

struct vbsf_mount_info_new
{
	char nullchar;			/* name cannot be '\0' -- we use this field
					 to distinguish between the old structure
					 and the new structure */
	char signature[3];		/* signature */
	int  length;			/* length of the whole structure */
	char name[MAX_HOST_NAME];	/* share name */
	char nls_name[MAX_NLS_NAME];	/* name of an I/O charset */
	int  uid;			/* user ID for all entries, default 0=root */
	int  gid;			/* group ID for all entries, default 0=root */
	int  ttl;			/* time to live */
	int  dmode;			/* mode for directories if != 0xffffffff */
	int  fmode;			/* mode for regular files if != 0xffffffff */
	int  dmask;			/* umask applied to directories */
	int  fmask;			/* umask applied to regular files */
};

static int hyper_setup_shared(struct hyper_pod *pod)
{
	struct vbsf_mount_info_new mntinf;

	if (pod->tag == NULL) {
		fprintf(stdout, "no shared directroy\n");
		return 0;
	}

	if (hyper_mkdir("/tmp/hyper/shared") < 0) {
		perror("fail to create /tmp/hyper/shared");
		return -1;
	}

	bzero(&mntinf, sizeof(mntinf));
	mntinf.nullchar = '\0';
	mntinf.signature[0]	= VBSF_MOUNT_SIGNATURE_BYTE_0;
	mntinf.signature[1]	= VBSF_MOUNT_SIGNATURE_BYTE_1;
	mntinf.signature[2]	= VBSF_MOUNT_SIGNATURE_BYTE_2;
	mntinf.length		= sizeof(mntinf);
	mntinf.dmode		= ~0U;
	mntinf.fmode		= ~0U;
	strcpy(mntinf.name, pod->tag);

	if (mount(NULL, "/tmp/hyper/shared", "vboxsf",
		  MS_NODEV, &mntinf) < 0) {
		perror("fail to mount shared dir");
		return -1;
	}

	return 0;
}
#else
static int hyper_setup_shared(struct hyper_pod *pod)
{
	if (pod->tag == NULL) {
		fprintf(stdout, "no shared directroy\n");
		return 0;
	}

	if (hyper_mkdir("/tmp/hyper/shared") < 0) {
		perror("fail to create /tmp/hyper/shared");
		return -1;
	}

	if (mount(pod->tag, "/tmp/hyper/shared", "9p",
		  MS_MGC_VAL| MS_NODEV, "trans=virtio,cache=loose") < 0) {

		perror("fail to mount shared dir");
		return -1;
	}

	return 0;
}
#endif

static int hyper_setup_pod(struct hyper_pod *pod)
{
	/* create tmp proc directroy */
	if (hyper_mkdir("/tmp/hyper/proc") < 0) {
		perror("create tmp proc failed");
		return -1;
	}

	if (hyper_setup_network(pod) < 0) {
		fprintf(stderr, "setup network failed\n");
		return -1;
	}

	if (hyper_setup_dns(pod) < 0) {
		fprintf(stderr, "setup network failed\n");
		return -1;
	}

	if (hyper_setup_shared(pod) < 0) {
		fprintf(stderr, "setup shared directory failed\n");
		return -1;
	}

	if (hyper_setup_container(pod) < 0) {
		fprintf(stderr, "start container failed\n");
		return -1;
	}

	return 0;
}

static void hyper_print_uptime(void)
{
	char buf[128];
	int fd = open("/proc/uptime", O_RDONLY);

	if (fd < 0)
		return;
	memset(buf, 0, sizeof(buf));
	if (read(fd, buf, sizeof(buf)))
		fprintf(stdout, "uptime %s\n", buf);

	close(fd);
}

static void hyper_kill_process(int pid)
{
	char path[64];
	char *line = NULL, *ignore = "SigIgn:";
	size_t len = 0;
	ssize_t read;
	FILE *file;
	char *sub;

	sprintf(path, "/proc/%u/status", pid);

	fprintf(stdout, "fopen %s\n", path);
	file = fopen(path, "r");
	if (file == NULL) {
		perror("can not open process proc status file");
		return;
	}

	while ((read = getline(&line, &len, file)) != -1) {
		long mask;

		if (strstr(line, ignore) == NULL)
			continue;

		sub = line + strlen(ignore);
		fprintf(stdout, "find sigign %s", sub);

		mask = atol(sub);
		fprintf(stdout, "mask is %ld\n", mask);

		if ((mask >> (SIGTERM - 1)) & 0x1) {
			fprintf(stdout, "signal term is ignored, kill it\n");
			kill(pid, SIGKILL);
		}

		break;
	}

	fclose(file);
	free(line);
}

static void hyper_term_all(struct hyper_pod *pod)
{
	int npids = 0;
	int index = 0;
	int pid;
	DIR *dp;
	struct dirent *de;
	pid_t *pids = NULL;

	dp = opendir("/proc");
	if (dp == NULL)
		return;

	while ((de = readdir(dp)) && de != NULL) {
		if (!isdigit(de->d_name[0]))
			continue;
		pid = atoi(de->d_name);
		if (pid == 1)
			continue;
		if (index <= npids) {
			pids = realloc(pids, npids + 16384);
			if (pids == NULL)
				return;
			npids += 16384;
		}

		pids[index++] = pid;
	}

	fprintf(stdout, "Sending SIGTERM\n");

	for (--index; index >= 0; --index) {
		fprintf(stdout, "kill process %d\n", pids[index]);
		kill(pids[index], SIGTERM);
	}

	free(pids);
	closedir(dp);

	for (index = 0; index < pod->c_num; index++) {
		hyper_kill_process(pod->c[index].exec.pid);
	}
}

static void hyper_cleanup_pod(struct hyper_pod *pod)
{
	close(pod->sig.fd);
	hyper_reset_event(&pod->sig);

	hyper_term_all(pod);
	hyper_handle_exit(pod, pod->ctl.fd, 1, 0);

	pod->init_pid = 0;

	close(pod->ctl.fd);
	hyper_reset_event(&pod->ctl);

	hyper_unmount_all();

	_exit(0);
}

static int hyper_start_pod(char *json, int length)
{
	struct hyper_pod *pod = &global_pod;

	fprintf(stdout, "call hyper_start_pod, json %s, len %d\n", json, length);

	if (pod->init_pid)
		fprintf(stdout, "pod init_pid exist %d\n", pod->init_pid);

	if (hyper_parse_pod(pod, json, length) < 0) {
		fprintf(stderr, "parse pod json failed\n");
		return -1;
	}

	if (hyper_setup_pod(pod) < 0) {
		hyper_shutdown(pod);
		return -1;
	}

	return 0;
}

static void hyper_cleanup_shared(struct hyper_pod *pod)
{
	if (pod->tag == NULL) {
		fprintf(stdout, "no shared directroy\n");
		return;
	}

	free(pod->tag);
	if (umount("/tmp/hyper/shared") < 0 &&
	    umount2("/tmp/hyper/shared", MNT_DETACH)) {
		perror("fail to umount 9p dir");
		return;
	}

	if (rmdir("/tmp/hyper/shared") < 0)
		perror("fail to delete /tmp/hyper/shared");
}

static int hyper_send_stoppod(int fd)
{
	if (hyper_setfd_block(fd) < 0) {
		perror("set fd BLOCK failed");
		return -1;
	}

	if (hyper_send_type(fd, STOPPOD) < 0) {
		fprintf(stderr, "send STOPPOD message failed\n");
		return -1;
	}

	hyper_event_read(&ctl.ctl);

	return 0;
}

static int hyper_stop_pod(struct hyper_pod *pod)
{
	fprintf(stdout, "hyper_stop_pod init_pid %d\n", pod->init_pid);
	if (pod->init_pid == 0) {
		fprintf(stdout, "container init pid is already exit\n");
		return 0;
	}

	/* Make hyper ctl_pipe blocked */
	hyper_send_stoppod(ctl.ctl.fd);

	hyper_cleanup_exec(pod);
	hyper_cleanup_container(pod);
	hyper_cleanup_network(pod);
	hyper_cleanup_dns(pod);
	hyper_cleanup_shared(pod);

	free(pod->hostname);

	sync();
	/* Wait for pod init ack */
	close(ctl.ctl.fd);
	hyper_reset_event(&ctl.ctl);
	return 0;
}

static int hyper_setup_ctl_channel(char *name)
{
	int ret = hyper_open_channel(name, 0);

	if (ret < 0)
		return ret;

	fprintf(stdout, "send ready message\n");
	if (hyper_send_type(ret, READY) < 0) {
		perror("send READY MESSAGE failed\n");
		goto out;
	}

	return ret;
out:
	close(ret);
	return -1;
}

static int hyper_setup_tty_channel(char *name)
{
	int ret = hyper_open_channel(name, O_NONBLOCK);
	if (ret < 0)
		return -1;

	return ret;
}

static int hyper_ttyfd_handle(struct hyper_event *de, uint32_t len)
{
	struct hyper_buf *rbuf = &de->rbuf;
	struct hyper_pod *pod = de->ptr;
	struct hyper_exec *exec;
	struct hyper_buf *wbuf;
	uint64_t seq = 0;
	int size;

	seq = hyper_get_be64(rbuf->data);

	dprintf(stdout, "\n%s seq %" PRIu64", len %" PRIu32"\n", __func__, seq, len - 12);

	exec = hyper_find_exec_by_seq(pod, seq);
	if (exec == NULL) {
		wbuf = &de->wbuf;
		fprintf(stderr, "can't find exec whose seq is %" PRIu64 "\n", seq);

		/* goodbye */
		if (wbuf->get + 12 > wbuf->size)
			return 0;

		hyper_set_be64(wbuf->data + wbuf->get, seq);
		hyper_set_be32(wbuf->data + wbuf->get + 8, 12);
		wbuf->get += 12;

		if (hyper_modify_event(ctl.efd, de, EPOLLIN | EPOLLOUT) < 0) {
			fprintf(stderr, "modify ctl tty event to in & out failed\n");
			return -1;
		}

		return 0;
	}

	dprintf(stdout, "find exec %s pid %d, seq is %" PRIu64 "\n",
		exec->id ? exec->id : "pod", exec->pid, exec->seq);
	wbuf = &exec->e.wbuf;

	size = wbuf->size - wbuf->get;
	if (size == 0)
		return 0;

	/* Data may lost since pts buffer is full. do not allow one exec pts occupy all
	 * of the tty buff. */
	if (size > (len - 12))
		size = (len - 12);

	if (size > 0) {
		memcpy(wbuf->data + wbuf->get, rbuf->data + 12, size);
		wbuf->get += size;
		if (hyper_modify_event(ctl.efd, &exec->e, EPOLLIN | EPOLLOUT) < 0) {
			fprintf(stderr, "modify exec pts event to in & out failed\n");
			return -1;
		}
	}

	return 0;
}

static int hyper_channel_handle(struct hyper_event *de, uint32_t len)
{
	struct hyper_buf *buf = &de->rbuf;
	struct hyper_pod *pod = de->ptr;
	uint32_t type = 0;
	int i, ret = 0;

	for (i = 0; i < buf->get; i++)
		fprintf(stdout, "%0x ", buf->data[i]);

	type = hyper_get_be32(buf->data);

	fprintf(stdout, "\n %s, type %" PRIu32 ", len %" PRIu32 "\n",
		__func__, type, len);

	pod->type = type;
	switch (type) {
	case STARTPOD:
		ret = hyper_start_pod((char *)buf->data + 8, len - 8);
		hyper_print_uptime();
		break;
	case STOPPOD:
		ret = hyper_stop_pod(pod);
		break;
	case DESTROYPOD:
		fprintf(stdout, "get DESTROYPOD message\n");
		hyper_shutdown(pod);
		return 0;
	case EXECCMD:
		ret = hyper_exec_cmd((char *)buf->data + 8, len - 8);
		break;
	case PING:
	case GETPOD:
		break;
	case READY:
		ret = hyper_rescan();
		break;
	case WINSIZE:
		ret = hyper_set_win_size((char *)buf->data + 8, len - 8);
		break;
	default:
		ret = -1;
		break;
	}

	if (ret < 0)
		hyper_send_type(de->fd, ERROR);
	else
		hyper_send_type(de->fd, ACK);

	return 0;
}

static struct hyper_event_ops hyper_channel_ops = {
	.read		= hyper_event_read,
	.handle		= hyper_channel_handle,
	.rbuf_size	= 10240,
	.len_offset	= 4,
	/* TODO: vbox hyper should support channel ack */
	.ack		= 1,
};

static struct hyper_event_ops hyper_ttyfd_ops = {
	.read		= hyper_event_read,
	.write		= hyper_event_write,
	.handle		= hyper_ttyfd_handle,
	.rbuf_size	= 4096,
	.wbuf_size	= 10240,
	.len_offset	= 8,
};

static struct hyper_event_ops hyper_signal_ops = {
	.read		= hyper_signal_loop,
	.hup		= hyper_event_hup,
};

static int hyper_loop(void)
{
	int i, n;
	struct epoll_event *events;
	struct hyper_pod *pod = &global_pod;

	ctl.efd = epoll_create1(EPOLL_CLOEXEC);
	if (ctl.efd < 0) {
		perror("epoll_create failed");
		return -1;
	}

	fprintf(stdout, "hyper_init_event hyper channel event %p, ops %p, fd %d\n",
		&ctl.chan, &hyper_channel_ops, ctl.chan.fd);
	if (hyper_init_event(&ctl.chan, &hyper_channel_ops, pod) < 0 ||
	    hyper_add_event(ctl.efd, &ctl.chan, EPOLLIN) < 0) {
		return -1;
	}

	fprintf(stdout, "hyper_init_event hyper ttyfd event %p, ops %p, fd %d\n",
		&ctl.tty, &hyper_ttyfd_ops, ctl.tty.fd);
	if (hyper_init_event(&ctl.tty, &hyper_ttyfd_ops, pod) < 0 ||
	    hyper_add_event(ctl.efd, &ctl.tty, EPOLLIN) < 0) {
		return -1;
	}

	fprintf(stdout, "hyper_init_event hyper signal event %p, ops %p, fd %d\n",
		&ctl.sig, &hyper_signal_ops, ctl.sig.fd);
	if (hyper_init_event(&ctl.sig, &hyper_signal_ops, pod) < 0 ||
	    hyper_add_event(ctl.efd, &ctl.sig, EPOLLIN) < 0) {
		return -1;
	}

	events = calloc(MAXEVENTS, sizeof(*events));

	while (1) {
		n = epoll_wait(ctl.efd, events, MAXEVENTS, -1);
		fprintf(stdout, "%s epoll_wait %d\n", __func__, n);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("hyper wait event failed");
			return -1;
		}
		for (i = 0; i < n; i++) {
			if (hyper_handle_event(ctl.efd, &events[i]) < 0)
				return -1;
		}
	}

	free(events);
	close(ctl.efd);
	return 0;
}

int main(int argc, char *argv[])
{
	char *cmdline, *ctl_serial, *tty_serial;
	sigset_t mask;

	if (hyper_mkdir("/dev") < 0 ||
	    hyper_mkdir("/sys") < 0 ||
	    hyper_mkdir("/proc") < 0) {
		perror("create basic directroy failed");
		return -1;
	}

	if (mount("proc", "/proc", "proc", 0, NULL) == -1) {
		perror("mount proc failed");
		return -1;
	}

	hyper_print_uptime();

	if (mount("sysfs", "/sys", "sysfs", 0, NULL) == -1) {
		perror("mount sysfs failed");
		return -1;
	}

	if (mount("dev", "/dev", "devtmpfs", 0, NULL) == -1) {
		perror("mount sysfs failed");
		return -1;
	}

	if (hyper_mkdir("/dev/pts") < 0) {
		perror("create basic directroy failed");
		return -1;
	}

	if (mount("devpts", "/dev/pts", "devpts", 0, NULL) == -1) {
		perror("mount devpts failed");
		return -1;
	}

	cmdline = read_cmdline();

	setsid();

	ioctl(STDIN_FILENO, TIOCSCTTY, 1);

#ifdef WITH_VBOX
	ctl_serial = "/dev/ttyS0";
	tty_serial = "/dev/ttyS1";

	if (hyper_insmod("/vboxguest.ko") < 0 ||
	    hyper_insmod("/vboxsf.ko") < 0) {
		fprintf(stderr, "fail to load modules\n");
		return -1;
	}
#else
	ctl_serial = "sh.hyper.channel.0";
	tty_serial = "sh.hyper.channel.1";
#endif

	setenv("PATH", "/bin:/sbin/:/usr/bin/:/usr/sbin/", 1);

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("sigprocmask SIGCHLD failed");
		return -1;
	}

	ctl.sig.fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (ctl.sig.fd < 0) {
		perror("create signalfd failed");
		return -1;
	}

	ctl.chan.fd = hyper_setup_ctl_channel(ctl_serial);
	if (ctl.chan.fd < 0) {
		fprintf(stderr, "fail to setup hyper control serial port\n");
		goto out1;
	}

	ctl.tty.fd = hyper_setup_tty_channel(tty_serial);
	if (ctl.tty.fd < 0) {
		fprintf(stderr, "fail to setup hyper tty serial port\n");
		goto out2;
	}

	hyper_loop();

	close(ctl.tty.fd);
out2:
	close(ctl.chan.fd);
out1:
	close(ctl.sig.fd);

	free(cmdline);

	return 0;
}
