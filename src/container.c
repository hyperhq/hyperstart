#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mntent.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include "util.h"
#include "hyper.h"
#include "parse.h"
#include "syscall.h"

static int container_populate_volume(char *src, char *dest)
{
	struct stat st;

	fprintf(stdout, "populate volumes from %s to %s\n", src, dest);
	/* FIXME: check if has data in volume, (except lost+found) */

	if (stat(dest, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "the _data in volume %s is not directroy\n", dest);
			return -1;
		}

		return 0;
	}

	if (errno != ENOENT) {
		perror("access to volume failed\n");
		return -1;
	}

	if (hyper_mkdir(dest) < 0) {
		fprintf(stderr, "fail to create directroy %s\n", dest);
		return -1;
	}

	return hyper_copy_dir(src, dest);
}

static int container_setup_volume(struct hyper_container *container)
{
	int i;
	char dev[512], path[512];
	struct volume *vol;

	for (i = 0; i < container->vols_num; i++) {
		char volume[512];
		char mountpoint[512];
		vol = &container->vols[i];

		if (vol->scsiaddr)
			hyper_find_sd(vol->scsiaddr, &vol->device);

		sprintf(dev, "/dev/%s", vol->device);
		sprintf(path, "/tmp/%s", vol->mountpoint);
		sprintf(volume, "/%s/_data", path);
		sprintf(mountpoint, "./%s", vol->mountpoint);

		fprintf(stdout, "mount %s to %s, tmp path %s\n",
			dev, vol->mountpoint, path);

		if (hyper_mkdir(path) < 0 || hyper_mkdir(mountpoint) < 0) {
			perror("create volume dir failed");
			return -1;
		}

		if (mount(dev, path, vol->fstype, 0, NULL) < 0) {
			perror("mount volume device faled");
			return -1;
		}

		if (vol->docker) {
			if (container->initialize &&
			    (container_populate_volume(mountpoint, volume) < 0)) {
				fprintf(stderr, "fail to populate volume %s\n", mountpoint);
				return -1;
			}
		} else if (hyper_mkdir(volume) < 0) {
			fprintf(stderr, "fail to create directroy %s\n", volume);
			return -1;
		}

		if (mount(volume, mountpoint, NULL, MS_BIND, NULL) < 0) {
			perror("mount volume device faled");
			return -1;
		}

		if (vol->readonly &&
		    mount(volume, mountpoint, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
			perror("mount fsmap faled");
			return -1;
		}

		umount(path);
	}

	for (i = 0; i < container->maps_num; i++) {
		struct stat st;
		char src[512];
		struct fsmap *map = &container->maps[i];
		char mountpoint[512];

		sprintf(src, "/tmp/hyper/shared/%s", map->source);
		sprintf(mountpoint, "./%s", map->path);
		fprintf(stdout, "mount %s to %s\n", src, mountpoint);

		stat(src, &st);
		if (st.st_mode & S_IFDIR) {
			if (hyper_mkdir(mountpoint) < 0) {
				perror("create map dir failed");
				continue;
			}

			if (map->docker && container->initialize &&
			    (container_populate_volume(mountpoint, src) < 0)) {
				fprintf(stderr, "fail to populate volume %s\n", mountpoint);
				continue;
			}
		} else {
			int fd = open(mountpoint, O_CREAT|O_WRONLY, 0755);
			if (fd < 0) {
				perror("create map file failed");
				continue;
			}
			close(fd);
		}

		if (mount(src, mountpoint, NULL, MS_BIND, NULL) < 0) {
			perror("mount fsmap faled");
			continue;
		}

		if (map->readonly == 0)
			continue;

		if (mount(src, mountpoint, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0)
			perror("mount fsmap faled");
	}

	return 0;
}

static int container_setup_mount(struct hyper_container *container)
{
	char src[512];

	// current dir is container rootfs, the operations on "./PATH" are the operations on container's "/PATH"
	hyper_mkdir("./proc");
	hyper_mkdir("./sys");
	hyper_mkdir("./dev");

	if (mount("proc", "./proc", "proc", MS_NOSUID| MS_NODEV| MS_NOEXEC, NULL) < 0 ||
	    mount("sysfs", "./sys", "sysfs", MS_NOSUID| MS_NODEV| MS_NOEXEC, NULL) < 0 ||
	    mount("devtmpfs", "./dev", "devtmpfs", MS_NOSUID, NULL) < 0) {
		perror("mount basic filesystem for container failed");
		return -1;
	}

	if (hyper_mkdir("./dev/shm") < 0) {
		fprintf(stderr, "create /dev/shm failed\n");
		return -1;
	}

	if (mount("tmpfs", "./dev/shm/", "tmpfs", MS_NOSUID| MS_NODEV, NULL) < 0) {
		perror("mount shm failed");
		return -1;
	}

	if (hyper_mkdir("./dev/pts") < 0) {
		fprintf(stderr, "create /dev/pts failed\n");
		return -1;
	}

	if (sprintf(src, "/tmp/hyper/%s/devpts", container->id) < 0) {
		fprintf(stderr, "get container devpts failed\n");
		return -1;
	}

	if (mount(src, "./dev/pts/", NULL, MS_BIND, NULL) < 0) {
		perror("move pts to /dev/pts failed");
		return -1;
	}

	if (unlink("./dev/ptmx") < 0)
		perror("remove /dev/ptmx failed");
	if (symlink("/dev/pts/ptmx", "./dev/ptmx") < 0)
		perror("link /dev/pts/ptmx to /dev/ptmx failed");

	symlink("/proc/self/fd", "./dev/fd");
	symlink("/proc/self/fd/0", "./dev/stdin");
	symlink("/proc/self/fd/1", "./dev/stdout");
	symlink("/proc/self/fd/2", "./dev/stderr");

	return 0;
}

static int container_recreate_file(char *filename)
{
	struct stat stbuf;

	fprintf(stdout, "recreate file %s\n", filename);
	if (stat(filename, &stbuf) < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "failed to stat %s: %d\n", filename, errno);
			return -1;
		}
		return hyper_create(filename);
	}
	if (stbuf.st_mode & S_IFREG && stbuf.st_size == 0)
		return 0;

	hyper_unlink(filename);
	return hyper_create(filename);
}

static int container_recreate_symlink(char *oldpath, char *newpath)
{
	fprintf(stdout, "recreate symlink %s to %s\n", newpath, oldpath);
	hyper_unlink(newpath);
	return hyper_symlink(oldpath, newpath);
}

/*
 * Docker uses the init layer to protect against unwanted side effects on
 * the rw layer. We recreate the same files here to have similar effect.
 * Docker also creates directories like /dev/pts, /dev/shm, /proc, /sys,
 * which we have over ridden in container_setup_mount, so no need to create
 * them here.
 */
static int container_setup_init_layer(struct hyper_container *container,
				      int setup_dns)
{
	if (!container->initialize)
		return 0;

	hyper_mkdir("./etc/");

	if (setup_dns && container_recreate_file("./etc/resolv.conf") < 0)
		return -1;

	if (container_recreate_file("./etc/hosts") < 0)
		return -1;

	if (container_recreate_file("./etc/hostname") < 0)
		return -1;

	if (container_recreate_symlink("/proc/mounts", "./etc/mtab") < 0)
		return -1;

	return 0;
}

static int container_setup_sysctl(struct hyper_container *container)
{
	int i, size, len, l, fd;
	struct sysctl *sys;

	for (i = 0; i < container->sys_num; i++) {
		char path[256];

		len = 0;
		sys = &container->sys[i];
		size = strlen(sys->value);

		sprintf(path, "/proc/sys/%s", sys->path);
		fprintf(stdout, "sysctl %s value %s\n", sys->path, sys->value);

		fd = open(path, O_WRONLY);
		if (fd < 0) {
			perror("open file failed");
			goto out;
		}

		while (len < size) {
			l = write(fd, sys->value + len, size - len);
			if (l < 0) {
				perror("fail to write sysctl");
				close(fd);
				goto out;
			}
			len += l;
		}

		close(fd);
	}

	return 0;
out:
	return -1;
}

static int container_setup_dns(struct hyper_container *container)
{
	int fd;
	struct stat st;
	char *src = "/tmp/hyper/resolv.conf";

	if (stat(src, &st) < 0) {
		if (errno == ENOENT) {
			fprintf(stdout, "no dns configured\n");
			return 0;
		}

		perror("stat resolve.conf failed");
		return -1;
	}

	hyper_mkdir("./etc");

	fd = open("./etc/resolv.conf", O_CREAT| O_WRONLY, 0644);
	if (fd < 0) {
		perror("create /etc/resolv.conf failed");
		return -1;
	}
	close(fd);

	if (mount(src, "./etc/resolv.conf", NULL, MS_BIND, NULL) < 0) {
		perror("bind to /etc/resolv.conf failed");
		return -1;
	}

	return 0;
}

static int container_setup_workdir(struct hyper_container *container)
{
	if (container->initialize) {
		// create workdir
		hyper_mkdir(container->exec.workdir);
	}

	if (container->exec.workdir && chdir(container->exec.workdir) < 0) {
		perror("change work directory failed");
		return -1;
	}

	return 0;
}

static int container_setup_tty(int fd, struct hyper_container *container)
{
	return hyper_dup_exec_tty(fd, &container->exec);
}

static int hyper_rescan_scsi(void)
{
	struct dirent **list;
	struct dirent *dir;
	int fd = -1, i, num;
	char path[256];

	num = scandir("/sys/class/scsi_host/", &list, NULL, NULL);
	if (num < 0) {
		perror("scan /sys/calss/virtio-ports/ failed");
		return -1;
	}

	memset(path, 0, sizeof(path));

	for (i = 0; i < num; i++) {
		dir = list[i];
		if (dir->d_name[0] == '.')
			continue;

		if (snprintf(path, sizeof(path), "/sys/class/scsi_host/%s/scan",
			     dir->d_name) < 0) {
			fprintf(stderr, "get scsi host device %s path failed\n",
				dir->d_name);
			continue;
		}

		fprintf(stdout, "path %s\n", path);
		fd = open(path, O_WRONLY);
		if (fd < 0) {
			perror("open path failed");
			continue;
		}

		if (write(fd, "- - - \n", 7) < 0)
			perror("write to scan failed");

		close(fd);
	}

	fprintf(stdout, "finish scan scsi\n");
	return 0;
	free(list);
}

struct hyper_container_arg {
	struct hyper_container	*c;
	struct hyper_pod	*pod;
	int			ipcns;
	int			utsns;
	int			pipe[2];
};

static int hyper_container_init(void *data)
{
	struct hyper_container_arg *arg = data;
	struct hyper_container *container = arg->c;
	char root[512], rootfs[512];
	int setup_dns;

	fprintf(stdout, "%s in\n", __func__);
	if (container->exec.argv == NULL) {
		fprintf(stdout, "no cmd!\n");
		goto fail;
	}

	if (setns(arg->ipcns, CLONE_NEWIPC) < 0) {
		perror("setns to ipcns of pod init faild");
		goto fail;
	}

	if (setns(arg->utsns, CLONE_NEWUTS) < 0) {
		perror("setns to ipcns of pod init faild");
		goto fail;
	}

	if (hyper_rescan_scsi() < 0) {
		fprintf(stdout, "rescan scsi failed\n");
		goto fail;
	}

	// set additinal env before config so that the config can overwrite it
	setenv("HOME", "/root", 1);
	setenv("HOSTNAME", arg->pod->hostname, 1);
	if (container->exec.tty)
		setenv("TERM", "xterm", 1);
	else
		unsetenv("TERM");

	if (hyper_setup_env(container->exec.envs, container->exec.envs_num) < 0) {
		fprintf(stdout, "setup env failed\n");
		goto fail;
	}

	if (mount("", "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
		perror("mount SLAVE failed");
		goto fail;
	}

	if (mount("", "/", NULL, MS_PRIVATE|MS_REC, NULL) < 0) {
		perror("mount PRIVATE failed");
		goto fail;
	}

	sprintf(root, "/tmp/hyper/%s/root/", container->id);
	if (hyper_mkdir(root) < 0) {
		perror("make root directroy failed");
		goto fail;
	}

	fprintf(stdout, "container root directory %s\n", root);

	if (container->fstype) {
		char dev[128];

		if (container->scsiaddr)
			hyper_find_sd(container->scsiaddr, &container->image);

		sprintf(dev, "/dev/%s", container->image);
		fprintf(stdout, "device %s\n", dev);

		if (mount(dev, root, container->fstype, 0, NULL) < 0) {
			perror("mount device failed");
			goto fail;
		}
	} else {
		char path[512];

		sprintf(path, "/tmp/hyper/shared/%s/", container->image);
		fprintf(stdout, "src directory %s\n", path);

		if (mount(path, root, NULL, MS_BIND, NULL) < 0) {
			perror("mount src dir failed");
			goto fail;
		}
	}

	fprintf(stdout, "root directory for container is %s/%s, init task %s\n",
		root, container->rootfs, container->exec.argv[0]);

	sprintf(rootfs, "%s/%s/", root, container->rootfs);
	if (mount(rootfs, rootfs, NULL, MS_BIND|MS_REC, NULL) < 0) {
		perror("failed to bind rootfs");
		goto fail;
	}
	chdir(rootfs);

	/*
	 * Recreate dns resolver iif configured by pod spec. Other cases
	 * are handled by hyperd instead.
	 */
	setup_dns = arg->pod->dns != NULL && arg->pod->d_num > 0;
	if (container_setup_init_layer(container, setup_dns) < 0) {
		fprintf(stderr, "container sets up init layer failed\n");
		goto fail;
	}

	if (container_setup_mount(container) < 0) {
		fprintf(stderr, "container sets up mount failed\n");
		goto fail;
	}

	if (container_setup_volume(container) < 0) {
		fprintf(stderr, "container sets up voulme failed\n");
		goto fail;
	}

	if (container_setup_dns(container) < 0) {
		fprintf(stderr, "container sets up dns failed\n");
		goto fail;
	}

	// manipulate the rootfs of the container/namespace: move the prepared path @rootfs to /
	if (mount(rootfs, "/", NULL, MS_MOVE, NULL) < 0) {
		perror("failed to move rootfs");
		goto fail;
	}
	/* pivot_root won't work, see
	 * Documention/filesystem/ramfs-rootfs-initramfs.txt */
	chroot(".");

	chdir("/");

	if (container_setup_sysctl(container) < 0) {
		fprintf(stderr, "container sets up sysctl failed\n");
		goto fail;
	}

	if (container_setup_workdir(container) < 0) {
		fprintf(stderr, "container sets up work directory failed\n");
		goto fail;
	}

	fflush(stdout);

	if (container_setup_tty(arg->pipe[1], container) < 0) {
		fprintf(stdout, "setup tty failed\n");
		goto fail;
	}

	execvp(container->exec.argv[0], container->exec.argv);
	perror("exec container command failed");

	_exit(-1);

fail:
	hyper_send_type(arg->pipe[1], ERROR);
	_exit(-1);
}

static int hyper_setup_pty(struct hyper_container *c)
{
	char root[512];

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

	if (hyper_setup_exec_tty(&c->exec) < 0) {
		fprintf(stderr, "setup container pts failed\n");
		return -1;
	}

	return 0;
}

int hyper_start_container(struct hyper_container *container,
			  int utsns, int ipcns, struct hyper_pod *pod)
{
	int stacksize = getpagesize() * 4;
	struct hyper_container_arg arg = {
		.c	= container,
		.pod	= pod,
		.utsns	= utsns,
		.ipcns	= ipcns,
		.pipe	= {-1, -1},
	};
	int flags = CLONE_NEWNS | SIGCHLD;
	char path[128];
	uint32_t type;
	void *stack;
	int pid;

	if (container->image == NULL || container->exec.argv == NULL) {
		fprintf(stdout, "container root image %s, argv %p\n",
			container->image, container->exec.argv);
		goto fail;
	}

	if (hyper_setup_pty(container) < 0) {
		fprintf(stderr, "setup pty device for container failed\n");
		goto fail;
	}

	if (pipe2(arg.pipe, O_CLOEXEC) < 0) {
		perror("create pipe between pod init execcmd failed");
		goto fail;
	}

	if (hyper_watch_exec_pty(&container->exec, pod) < 0) {
		fprintf(stderr, "faile to watch container pty\n");
		goto fail;
	}

	stack = malloc(stacksize);
	if (stack == NULL) {
		perror("fail to allocate stack for container init");
		goto fail;
	}

	pid = clone(hyper_container_init, stack + stacksize, flags, &arg);
	free(stack);
	if (pid < 0) {
		perror("create child process failed");
		goto fail;
	}
	sprintf(path, "/proc/%d/ns/mnt", pid);

	container->ns = open(path, O_RDONLY | O_CLOEXEC);
	if (container->ns < 0) {
		perror("open container mount ns failed");
		goto fail;
	}

	/* wait for ready message */
	if (hyper_get_type(arg.pipe[0], &type) < 0 || type != READY) {
		fprintf(stderr, "wait for container started failed\n");
		goto fail;
	}

	container->exec.pid = pid;
	list_add_tail(&container->exec.list, &pod->exec_head);
	container->exec.ref++;

	close(arg.pipe[0]);
	close(arg.pipe[1]);

	fprintf(stdout, "container %s,init pid %d,ref %d\n", container->id, pid, container->exec.ref);
	return 0;
fail:
	close(arg.pipe[0]);
	close(arg.pipe[1]);
	close(container->ns);
	hyper_reset_event(&container->exec.stdinev);
	hyper_reset_event(&container->exec.stdoutev);
	hyper_reset_event(&container->exec.stderrev);
	container->ns = -1;
	fprintf(stdout, "container %s init exit code %d\n", container->id, -1);
	container->exec.code = -1;
	container->exec.seq = 0;
	container->exec.ref = 0;
	return -1;
}

struct hyper_container *hyper_find_container(struct hyper_pod *pod, char *id)
{
	struct hyper_container *c;

	list_for_each_entry(c, &pod->containers, list) {
		if (strlen(c->id) != strlen(id))
			continue;

		if (strncmp(c->id, id, strlen(id)))
			continue;

		return c;
	}

	return NULL;
}

void hyper_cleanup_container(struct hyper_container *c)
{
	char root[512];

	sprintf(root, "/tmp/hyper/%s/devpts/", c->id);
	if (umount(root) < 0 && umount2(root, MNT_DETACH))
		perror("umount devpts failed");

	close(c->ns);
	hyper_free_container(c);
}

void hyper_cleanup_containers(struct hyper_pod *pod)
{
	struct hyper_container *c, *n;

	list_for_each_entry_safe(c, n, &pod->containers, list)
		hyper_cleanup_container(c);

	pod->remains = 0;
}
