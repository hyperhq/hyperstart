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
#include "syscall.h"

struct hyper_pod global_pod = {
	.containers	=	LIST_HEAD_INIT(global_pod.containers),
	.exec_head	=	LIST_HEAD_INIT(global_pod.exec_head),
};
struct hyper_exec *global_exec;

#define MAXEVENTS	10

struct hyper_ctl ctl;

static struct hyper_event_ops hyper_signal_ops;
static int hyper_handle_exit(struct hyper_pod *pod);
static int hyper_stop_pod(struct hyper_pod *pod);

static int hyper_set_win_size(char *json, int length)
{
	struct hyper_win_size ws = {
		.tty = NULL,
	};
	struct winsize size;
	struct hyper_exec *exec;
	char path[128];
	int fd, ret;

	fprintf(stdout, "call hyper_win_size, json %s, len %d\n", json, length);
	if (hyper_parse_winsize(&ws, json, length) < 0) {
		fprintf(stderr, "set term size failed\n");
		return -1;
	}

	if (!ws.tty) {
		exec = hyper_find_exec_by_seq(&global_pod, ws.seq);
		if (exec == NULL) {
			fprintf(stdout, "can not find exec whose seq is %" PRIu64"\n", ws.seq);
			return 0;
		}

		fprintf(stdout, "find exec %s, pid is %d, seq is %" PRIu64"\n",
			exec->id ? exec->id : "pod", exec->pid, ws.seq);
		fd = dup(exec->ptyfd);
	} else {
		if (sprintf(path, "/dev/%s", ws.tty) < 0) {
			fprintf(stderr, "get tty device failed\n");
			return -1;
		}
		fd = hyper_open_serial_dev(path);
	}

	if (fd < 0) {
		perror("cannot open pty device to set term size");
		goto out;
	}

	size.ws_row = ws.row;
	size.ws_col = ws.column;

	ret = ioctl(fd, TIOCSWINSZ, &size);
	if (ret < 0)
		perror("cannot ioctl to set pty device term size");

	close(fd);
out:
	free(ws.tty);
	return ret;
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
	struct hyper_container *c;

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

	list_for_each_entry(c, &pod->containers, list)
		hyper_kill_process(c->exec.pid);
}

static int hyper_handle_exit(struct hyper_pod *pod)
{
	int pid, status;
	/* pid + exit code */
	uint8_t data[5];

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		data[4] = 0;

		if (WIFEXITED(status)) {
			data[4] = WEXITSTATUS(status);
			fprintf(stdout, "pid %d exit normally, status %" PRIu8 "\n",
				pid, data[4]);

		} else if (WIFSIGNALED(status)) {
			fprintf(stdout, "pid %d exit by signal, status %d\n",
				pid, WTERMSIG(status));
		}

		if (pod && hyper_handle_exec_exit(pod, pid, data[4]) < 0)
			fprintf(stderr, "signal_loop send eof failed\n");
	}

	return 0;
}

static int hyper_signal_loop(struct hyper_event *de)
{
	int size;
	struct signalfd_siginfo sinfo;
	struct hyper_pod *pod = de->ptr;

	fprintf(stdout, "%s write to ctl tty fd\n", __func__);

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

		hyper_handle_exit(pod);
	}

	return 0;
}

static int pod_init_loop(struct hyper_pod *pod)
{
	int i, n;
	struct epoll_event *events;

	pod->efd = epoll_create1(EPOLL_CLOEXEC);
	if (pod->efd < 0) {
		perror("epoll_create failed");
		return -1;
	}

	fprintf(stdout, "hyper_init_event pod signal event %p, ops %p, fd %d\n",
		&pod->sig, &hyper_signal_ops, pod->sig.fd);
	if (hyper_init_event(&pod->sig, &hyper_signal_ops, NULL) < 0 ||
	    hyper_add_event(pod->efd, &pod->sig, EPOLLIN) < 0) {
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

	pod->sig.fd = -1;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("sigprocmask SIGCHLD failed");
		goto fail;
	}

	pod->sig.fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (pod->sig.fd < 0) {
		perror("create pod signalfd failed");
		goto fail;
	}

	/* mount new proc directory */
	if (umount("/proc") < 0) {
		perror("umount proc filesystem failed\n");
		goto fail;
	}

	if (mount("proc", "/proc", "proc", MS_NOSUID| MS_NODEV| MS_NOEXEC, NULL) < 0) {
		perror("mount proc filesystem failed\n");
		goto fail;
	}

	if (sethostname(pod->hostname, strlen(pod->hostname)) < 0) {
		perror("set host name failed");
		goto fail;
	}

	if (hyper_send_type(arg->ctl_pipe[1], READY) < 0) {
		fprintf(stderr, "container init send ready message failed\n");
		goto fail;
	}

	close(arg->ctl_pipe[1]);

	pod_init_loop(pod);
	fprintf(stdout, "pod init exit\n");
out:
	_exit(-1);

fail:
	hyper_send_type(arg->ctl_pipe[1], ERROR);
	close(arg->ctl_pipe[1]);
	close(pod->sig.fd);

	goto out;
}

struct hyper_stage0_arg {
	struct hyper_pod	*pod;
	struct hyper_container	*container;
	int			ctl_pipe[2];
};

// stage0: enter the pidns
static int hyper_container_stage0(void *data)
{
	int pidns, ipcns, utsns, ret;
	struct hyper_container *c;
	struct hyper_stage0_arg *arg;
	struct hyper_pod *pod;
	char path[64];

	arg = data;
	pod = arg->pod;
	c   = arg->container;

	ret = pidns = ipcns = utsns = -1;

	sprintf(path, "/proc/%d/ns/pid", pod->init_pid);
	pidns = open(path, O_RDONLY| O_CLOEXEC);
	if (pidns < 0) {
		perror("fail to open pidns of pod init");
		goto out;
	}

	/* enter pidns of pod init, so the children of this process will run in
	 * pidns of pod init, see man 2 setns */
	if (setns(pidns, CLONE_NEWPID) < 0) {
		perror("enter pidns of pod init failed");
		goto out;
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

	ret = hyper_start_container(c, utsns, ipcns, pod);
out:
	if (hyper_send_type(arg->ctl_pipe[1], ret ? ERROR : READY) < 0) {
		fprintf(stderr, "container init send ready message failed\n");
	}

	close(pidns);
	close(utsns);
	close(ipcns);
	close(arg->ctl_pipe[0]);
	close(arg->ctl_pipe[1]);

	_exit(ret);
}

int hyper_start_container_stage0(struct hyper_container *c, struct hyper_pod *pod)
{
	int stacksize = getpagesize() * 4;
	void *stack = NULL;
	struct hyper_stage0_arg arg = {
		.pod		= pod,
		.container	= c,
		.ctl_pipe	= {-1, -1},
	};
	int ret = -1, pid;
	uint32_t type;


	if (pipe2(arg.ctl_pipe, O_CLOEXEC) < 0) {
		perror("create pipe between hyper init and pod init failed");
		goto out;
	}

	stack = malloc(stacksize);
	if (stack == NULL) {
		perror("fail to allocate stack for container init");
		goto out;
	}

	pid = clone(hyper_container_stage0, stack + stacksize, CLONE_VM| CLONE_FILES| SIGCHLD, &arg);
	free(stack);
	if (pid < 0) {
		perror("enter container pid ns failed");
		goto out;
	}

	/* Wait for container start */
	if (hyper_get_type(arg.ctl_pipe[0], &type) < 0) {
		perror("get enter_container_pidns ready message failed");
		goto out;
	}

	if (type != READY) {
		fprintf(stderr, "get incorrect enter_container_pidns message type %d, expect READY\n",
			type);
		goto out;
	}

	/* container process is spawned and ready to execute */
	pod->remains++;
	ret = 0;
out:
	close(arg.ctl_pipe[0]);
	close(arg.ctl_pipe[1]);
	return ret;
}

int hyper_start_containers(struct hyper_pod *pod)
{
	struct hyper_container *c;

	list_for_each_entry(c, &pod->containers, list) {
		if (hyper_start_container_stage0(c, pod) < 0)
			return -1;
	}

	return 0;
}

static int hyper_setup_container(struct hyper_pod *pod)
{
	int stacksize = getpagesize() * 4;
	int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC |
		    CLONE_NEWUTS;

	struct hyper_pod_arg arg = {
		.pod		= NULL,
		.ctl_pipe	= {-1, -1},
	};

	uint32_t type;
	void *stack;
	int ret = -1;

	if (hyper_socketpair(PF_UNIX, SOCK_STREAM, 0, arg.ctl_pipe) < 0) {
		perror("create pipe between hyper init and pod init failed");
		goto out;
	}

	stack = malloc(stacksize);
	if (stack == NULL) {
		perror("fail to allocate stack for container init");
		goto out;
	}

	arg.pod = pod;

	pod->init_pid = clone(hyper_pod_init, stack + stacksize, flags, &arg);
	free(stack);
	if (pod->init_pid < 0) {
		perror("create container init process failed");
		goto out;
	}
	fprintf(stdout, "pod init pid %d\n", pod->init_pid);

	/* Wait for container start */
	if (hyper_get_type(arg.ctl_pipe[0], &type) < 0) {
		perror("get container init ready message failed");
		goto out;
	}

	if (type != READY) {
		fprintf(stderr, "get incorrect message type %d, expect READY\n", type);
		goto out;
	}

	if (hyper_start_containers(pod) < 0) {
		fprintf(stderr, "start containers failed\n");
		goto out;
	}

	ret = 0;
out:
	close(arg.ctl_pipe[1]);
	close(arg.ctl_pipe[0]);
	if (ret < 0) {
		hyper_stop_pod(pod);
	}
	return ret;
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

	if (pod->share_tag == NULL) {
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
	strcpy(mntinf.name, pod->share_tag);

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
	if (pod->share_tag == NULL) {
		fprintf(stdout, "no shared directroy\n");
		return 0;
	}

	if (hyper_mkdir("/tmp/hyper/shared") < 0) {
		perror("fail to create /tmp/hyper/shared");
		return -1;
	}

	if (mount(pod->share_tag, "/tmp/hyper/shared", "9p",
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

static int hyper_destroy_pod(struct hyper_pod *pod)
{
	if (pod->init_pid == 0) {
		/* Pod stopped, just shutdown */
		hyper_shutdown();
	} else {
		/* Kill pod */
		hyper_term_all(pod);
	}
	return 0;
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
		hyper_destroy_pod(pod);
		return -1;
	}

	return 0;
}

static int hyper_new_container(char *json, int length)
{
	int ret;
	struct hyper_container *c;
	struct hyper_pod *pod = &global_pod;

	fprintf(stdout, "call hyper_new_container, json %s, len %d\n", json, length);

	if (!pod->init_pid) {
		fprintf(stdout, "the pod is not created yet\n");
		return -1;
	}

	c = hyper_parse_new_container(pod, json, length);
	if (c == NULL) {
		fprintf(stderr, "parse container json failed\n");
		return -1;
	}

	list_add_tail(&c->list, &pod->containers);
	ret = hyper_start_container_stage0(c, pod);
	if (ret < 0) {
		//TODO full grace cleanup
		hyper_cleanup_container(c);
	}

	return ret;
}

static int hyper_kill_container(char *json, int length)
{
	struct hyper_killer killer;
	struct hyper_container *c;
	struct hyper_pod *pod = &global_pod;
	int ret = -1;

	if (hyper_parse_kill_container(&killer, json, length) < 0) {
		goto out;
	}

	c = hyper_find_container(pod, killer.id);
	if (c == NULL) {
		fprintf(stderr, "can not find container whose id is %s\n", killer.id);
		goto out;
	}

	kill(c->exec.pid, killer.signal);
	ret = 0;
out:
	return ret;
}

static int hyper_cmd_write_file(char *json, int length)
{
	struct hyper_writter writter;
	struct hyper_container *c;
	struct hyper_pod *pod = &global_pod;
	int pipe[2] = {-1, -1};
	int pid, mntns = -1, fd;
	char path[512];
	int len = 0, size, ret = -1;

	fprintf(stdout, "%s\n", __func__);

	if (hyper_parse_write_file(&writter, json, length) < 0) {
		goto out;
	}

	c = hyper_find_container(pod, writter.id);
	if (c == NULL) {
		fprintf(stderr, "can not find container whose id is %s\n", writter.id);
		goto out;
	}

	if (pipe2(pipe, O_CLOEXEC) < 0) {
		perror("create writter pipe failed");
		goto out;
	}

	mntns = c->ns;
	if (mntns < 0) {
		perror("fail to open mnt ns");
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		perror("fail to fork writter process");
		goto out;
	} else if (pid > 0) {
		uint32_t type;

		if (hyper_get_type(pipe[0], &type) < 0 || type != READY) {
			fprintf(stderr, "get incorrect message type %d, expect READY\n", type);
			goto out;
		}

		ret = 0;
		goto out;
	}

	if (setns(mntns, CLONE_NEWNS) < 0) {
		perror("fail to enter container ns");
		goto exit;
	}

	sprintf(path, "/tmp/hyper/%s/root/%s/", c->id, c->rootfs);
	fprintf(stdout, "write file %s, data len %d\n", writter.file, writter.len);

	/* TODO: wait for container finishing setup root */
	if (chroot(path) < 0) {
		perror("chroot for exec command failed");
		goto exit;
	}

	fd = open(writter.file, O_CREAT| O_TRUNC| O_WRONLY, 0644);
	if (fd < 0) {
		perror("fail to open target file");
		goto exit;
	}

	while(len < writter.len) {
		size = write(fd, writter.data + len, writter.len - len);

		if (size < 0) {
			if (errno == EINTR)
				continue;

			perror("fail to write data to file");
			goto exit;
		}

		len += size;
	}
	ret = 0;
exit:
	hyper_send_type(pipe[1], ret ? ERROR : READY);
	_exit(0);
out:
	close(pipe[0]);
	close(pipe[1]);
	free(writter.id);
	free(writter.file);
	free(writter.data);

	return 0;
}

struct hyper_file_arg {
	int		mntns;
	int		pipe[2];
	char		*file;
	char		root[128];
	uint32_t	*datalen;
	uint8_t		**data;
};

static int hyper_do_cmd_read_file(void *data)
{
	struct stat st;
	int len = 0, size, fd, ret = -1;
	struct hyper_file_arg *arg = data;

	if (setns(arg->mntns, CLONE_NEWNS) < 0) {
		perror("fail to enter container ns");
		goto err;
	}

	fprintf(stdout, "read file %s\n", arg->file);

	/* TODO: wait for container finishing setup root */
	if (chroot(arg->root) < 0) {
		perror("chroot for exec command failed");
		goto err;
	}

	if (stat(arg->file, &st) < 0) {
		perror("fail to state file");
		goto err;
	}

	*arg->datalen = st.st_size;
	*arg->data = malloc(*arg->datalen);
	if (*arg->data == NULL) {
		fprintf(stderr, "allocate memory for reading file failed\n");
		goto err;
	}

	fd = open(arg->file, O_RDONLY);
	if (fd < 0) {
		perror("fail to open target file");
		goto err;
	}

	fprintf(stdout, "file length %d\n", *arg->datalen);
	while(len < *arg->datalen) {
		size = read(fd, *arg->data + len, *arg->datalen - len);

		if (size < 0) {
			if (errno == EINTR)
				continue;

			perror("fail to read data from file");
			goto err;
		}

		len += size;
	}

	fprintf(stdout, "read data %s\n", *arg->data);
	ret = 0;
err:
	hyper_send_type(arg->pipe[1], ret ? ERROR : READY);
	return ret;
}

static int hyper_cmd_read_file(char *json, int length, uint32_t *datalen, uint8_t **data)
{
	struct hyper_reader reader;
	struct hyper_container *c;
	struct hyper_pod *pod = &global_pod;
	struct hyper_file_arg arg = {
		.pipe = {-1, -1},
	};
	int stacksize = getpagesize() * 4;
	void *stack = NULL;
	int pid, ret = -1;
	uint32_t type;

	fprintf(stdout, "%s\n", __func__);

	if (hyper_parse_read_file(&reader, json, length) < 0) {
		goto out;
	}

	c = hyper_find_container(pod, reader.id);
	if (c == NULL) {
		fprintf(stderr, "can not find container whose id is %s\n", reader.id);
		goto out;
	}

	if (pipe2(arg.pipe, O_CLOEXEC) < 0) {
		perror("create reader pipe failed");
		goto out;
	}

	arg.mntns = c->ns;
	if (arg.mntns < 0) {
		perror("fail to open mnt ns");
		goto out;
	}

	arg.file = reader.file;
	arg.datalen = datalen;
	arg.data = data;
	sprintf(arg.root, "/tmp/hyper/%s/root/%s/", c->id, c->rootfs);

	stack = malloc(stacksize);
	if (stack == NULL) {
		perror("fail to allocate stack for container init");
		goto out;
	}

	pid = clone(hyper_do_cmd_read_file, stack + stacksize, CLONE_VM| SIGCHLD, &arg);
	free(stack);
	if (pid < 0) {
		perror("fail to fork writter process");
		goto out;
	}

	if (hyper_get_type(arg.pipe[0], &type) < 0 || type != READY) {
		fprintf(stderr, "%s to incorrect type %" PRIu32 "\n", __func__, type);
		goto out;
	}

	ret = 0;
out:
	close(arg.pipe[0]);
	close(arg.pipe[1]);
	free(reader.id);
	free(reader.file);

	return ret;
}

static void hyper_cleanup_hostname(struct hyper_pod *pod)
{
	free(pod->hostname);
	pod->hostname = NULL;
}

static void hyper_cleanup_shared(struct hyper_pod *pod)
{
	if (pod->share_tag == NULL) {
		fprintf(stdout, "no shared directroy\n");
		return;
	}

	free(pod->share_tag);
	pod->share_tag = NULL;
	if (umount("/tmp/hyper/shared") < 0 &&
	    umount2("/tmp/hyper/shared", MNT_DETACH)) {
		perror("fail to umount shared dir");
		return;
	}

	if (rmdir("/tmp/hyper/shared") < 0)
		perror("fail to delete /tmp/hyper/shared");

	sync();
}

void hyper_cleanup_pod(struct hyper_pod *pod)
{
	if (pod->init_pid) {
		hyper_kill_process(pod->init_pid);
		pod->init_pid = 0;
	}
	hyper_cleanup_containers(pod);
	hyper_cleanup_network(pod);
	hyper_cleanup_shared(pod);
	hyper_cleanup_dns(pod);
	hyper_cleanup_hostname(pod);
}

static int hyper_stop_pod(struct hyper_pod *pod)
{
	fprintf(stdout, "hyper_stop_pod init_pid %d\n", pod->init_pid);
	if (pod->init_pid == 0) {
		fprintf(stdout, "container init pid is already exit\n");
		hyper_send_type(ctl.chan.fd, ACK);
		return 0;
	}

	pod->init_pid = 0;
	hyper_term_all(pod);
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
	// if exec is exited, the event fd of exec is invalid. don't accept any input.
	if (exec->exit) {
		fprintf(stdout, "exec seq %" PRIu64 " exited, don't accept any input\n", exec->seq);
		return 0;
	}

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
	uint32_t type = 0, datalen = 0;
	uint8_t *data = NULL;
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
		hyper_stop_pod(pod);
		return 0;
		//break;
	case DESTROYPOD:
		fprintf(stdout, "get DESTROYPOD message\n");
		hyper_destroy_pod(pod);
		return 0;
	case EXECCMD:
		ret = hyper_exec_cmd((char *)buf->data + 8, len - 8);
		break;
	case WRITEFILE:
		ret = hyper_cmd_write_file((char *)buf->data + 8, len - 8);
		break;
	case READFILE:
		ret = hyper_cmd_read_file((char *)buf->data + 8, len - 8, &datalen, &data);
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
	case NEWCONTAINER:
		ret = hyper_new_container((char *)buf->data + 8, len - 8);
		break;
	case KILLCONTAINER:
		ret = hyper_kill_container((char *)buf->data + 8, len - 8);
		break;
	default:
		ret = -1;
		break;
	}

	if (ret < 0)
		hyper_send_msg_block(de->fd, ERROR, 0, NULL);
	else
		hyper_send_msg_block(de->fd, ACK, datalen, data);

	free(data);
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

	if (mount("proc", "/proc", "proc", MS_NOSUID| MS_NODEV| MS_NOEXEC, NULL) == -1) {
		perror("mount proc failed");
		return -1;
	}

	hyper_print_uptime();

	if (mount("sysfs", "/sys", "sysfs", MS_NOSUID| MS_NODEV| MS_NOEXEC, NULL) == -1) {
		perror("mount sysfs failed");
		return -1;
	}

	if (mount("dev", "/dev", "devtmpfs", MS_NOSUID, NULL) == -1) {
		perror("mount sysfs failed");
		return -1;
	}

	if (hyper_mkdir("/dev/pts") < 0) {
		perror("create basic directroy failed");
		return -1;
	}

	if (mount("devpts", "/dev/pts", "devpts", MS_NOSUID| MS_NOEXEC, NULL) == -1) {
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
