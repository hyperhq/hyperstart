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

static int container_setup_env(struct hyper_container *container)
{
	int i;
	struct env *env;

	for (i = 0; i < container->envs_num; i++) {
		env = &container->envs[i];

		setenv(env->env, env->value, 1);
	}

	return 0;
}

static int container_setup_volume(struct hyper_container *container)
{
	int i;
	char dev[512], path[512];
	struct volume *vol;

	for (i = 0; i < container->vols_num; i++) {
		vol = &container->vols[i];

		sprintf(dev, "/.oldroot/dev/%s", vol->device);
		sprintf(path, "/tmp/%s", vol->mountpoint);
		fprintf(stdout, "mount %s to %s\n", dev, vol->mountpoint);

		if (hyper_mkdir(path) < 0 || hyper_mkdir(vol->mountpoint) < 0) {
			fprintf(stdout, "mountpoint %s\n", vol->mountpoint);
			perror("create volume dir failed");
			continue;
		}

		if (mount(dev, path, vol->fstype, 0, NULL) < 0) {
			perror("mount volume device faled");
			continue;
		}

		if (mount(path, vol->mountpoint, NULL, MS_BIND, NULL) < 0) {
			perror("mount volume device faled");
			continue;
		}

		if (vol->readonly &&
		    mount(path, vol->mountpoint, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0)
			perror("mount fsmap faled");

		umount(path);
	}

	return 0;
}

static void container_unmount_oldroot(char *path)
{
	FILE *mtab;
	struct mntent *mnt;
	char *mntlist[128];
	int i;
	int n = 0;
	char *filesys;

	mtab = setmntent("/proc/mounts", "r");
	if (mtab == NULL) {
		fprintf(stderr, "cannot open /proc/mount");
		return;
	}

	while (n < 128 && (mnt = getmntent(mtab))) {
		if (strncmp(mnt->mnt_dir, path, strlen(path)))
			continue;
		mntlist[n++] = strdup(mnt->mnt_dir);
	}

	endmntent(mtab);

	for (i = n - 1; i >= 0; i--) {
		filesys = mntlist[i];
		fprintf(stdout, "umount %s\n", filesys);
		if (umount(mntlist[i]) < 0 && umount2(mntlist[i],
			   MNT_DETACH) < 0) {
			fprintf(stdout, "umount %s: %s failed\n",
				filesys, strerror(errno));
		}
	}
}

static int container_setup_mount(struct hyper_container *container)
{
	int i, fd;
	char src[512];
	struct fsmap *map;

	if (mount("proc", "/proc", "proc", 0, NULL) < 0 ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) < 0 ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) < 0) {
		perror("mount basic filesystem for container failed");
		return -1;
	}

	if (hyper_mkdir("/dev/pts") < 0) {
		fprintf(stderr, "create /dev/pts failed\n");
		return -1;
	}

	if (sprintf(src, "/.oldroot/tmp/hyper/%s/devpts", container->id) < 0) {
		fprintf(stderr, "get container devpts failed\n");
		return -1;
	}

	if (mount(src, "/dev/pts/", NULL, MS_BIND, NULL) < 0) {
		perror("move pts to /dev/pts failed");
		return -1;
	}

	if (unlink("/dev/ptmx") < 0)
		perror("remove /dev/ptmx failed");
	if (symlink("/dev/pts/ptmx", "/dev/ptmx") < 0)
		perror("link /dev/pts/ptmx to /dev/ptmx failed");

	for (i = 0; i < container->maps_num; i++) {
		struct stat st;

		map = &container->maps[i];

		sprintf(src, "/.oldroot/tmp/hyper/shared/%s", map->source);
		fprintf(stdout, "mount %s to %s\n", src, map->path);

		stat(src, &st);
		if (st.st_mode & S_IFDIR) {
			if (hyper_mkdir(map->path) < 0) {
				perror("create map dir failed");
				continue;
			}
		} else {
			fd = open(map->path, O_CREAT|O_WRONLY, 0755);
			if (fd < 0) {
				perror("create map file failed");
				continue;
			}
			close(fd);
		}

		if (mount(src, map->path, NULL, MS_BIND, NULL) < 0) {
			perror("mount fsmap faled");
			continue;
		}

		if (map->readonly == 0)
			continue;

		if (mount(src, map->path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0)
			perror("mount fsmap faled");
	}

	return 0;
}

static int container_setup_dns(struct hyper_container *container)
{
	int fd;
	struct stat st;
	char *src = "/.oldroot/tmp/hyper/resolv.conf";

	if (stat(src, &st) < 0) {
		if (errno == ENOENT) {
			fprintf(stdout, "no dns configured\n");
			return 0;
		}

		perror("stat resolve.conf failed");
		return -1;
	}

	hyper_mkdir("/etc");

	fd = open("/etc/resolv.conf", O_CREAT| O_WRONLY, 0644);
	if (fd < 0) {
		perror("create /etc/resolv.conf failed");
		return -1;
	}
	close(fd);

	if (mount(src, "/etc/resolv.conf", NULL, MS_BIND, NULL) < 0) {
		perror("bind to /etc/resolv.conf failed");
		return -1;
	}

	return 0;
}

static int container_setup_workdir(struct hyper_container *container)
{
	if (container->workdir && chdir(container->workdir) < 0) {
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
	int			pipe[2];
};

static int hyper_container_init(void *data)
{
	struct hyper_container_arg *arg = data;
	struct hyper_container *container = arg->c;
	char root[512], oldroot[512];

	fprintf(stdout, "%s in\n", __func__);
	if (container->exec.argv == NULL) {
		fprintf(stdout, "no cmd!\n");
		goto fail;
	}

	if (hyper_rescan_scsi() < 0) {
		fprintf(stdout, "rescan scsi failed\n");
		goto fail;
	}

	if (container_setup_env(container) < 0) {
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

	hyper_list_dir(root);
	sprintf(oldroot, "%s/%s/.oldroot", root, container->rootfs);
	if (hyper_mkdir(oldroot) < 0) {
		perror("make oldroot directroy failed");
		goto fail;
	}

	if (mount("/", oldroot, NULL, MS_BIND|MS_REC, NULL) < 0) {
		perror("bind oldroot failed");
		goto fail;
	}
	/* reuse oldroot array */
	sprintf(oldroot, "%s/%s/", root, container->rootfs);
	/* pivot_root won't work, see
	 * Documention/filesystem/ramfs-rootfs-initramfs.txt */
	chroot(oldroot);

	chdir("/");

	if (container_setup_volume(container) < 0) {
		fprintf(stderr, "container sets up voulme failed\n");
		goto fail;
	}

	if (container_setup_mount(container) < 0) {
		fprintf(stderr, "container sets up mount ns failed\n");
		goto fail;
	}

	if (container_setup_dns(container) < 0) {
		fprintf(stderr, "container sets up dns failed\n");
		goto fail;
	}

	if (container_setup_workdir(container) < 0) {
		fprintf(stderr, "container sets up work directory failed\n");
		goto fail;
	}

	container_unmount_oldroot("/.oldroot");

	fflush(stdout);

	if (container_setup_tty(arg->pipe[1], container) < 0) {
		fprintf(stdout, "setup tty failed\n");
		goto fail;
	}

	close(arg->pipe[0]);
	close(arg->pipe[1]);

	execvp(container->exec.argv[0], container->exec.argv);

	_exit(-1);

fail:
	container->exec.code = -1;
	hyper_send_type_block(arg->pipe[1], ERROR, 0);
	_exit(-1);
}

int hyper_start_container(struct hyper_container *container)
{
	int stacksize = getpagesize() * 4;
	void *stack = malloc(stacksize);
	struct hyper_container_arg arg = {
		.c = container,
	};
	int flags = CLONE_NEWNS | SIGCHLD;
	uint32_t type;
	int pid;

	if (container->image == NULL || container->exec.argv == NULL) {
		fprintf(stdout, "container root image %s, argv %p\n",
			container->image, container->exec.argv);
		goto fail;
	}

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, arg.pipe) < 0) {
		perror("create pipe between pod init execcmd failed");
		goto fail;
	}

	pid = clone(hyper_container_init, stack + stacksize, flags, &arg);
	free(stack);
	if (pid < 0) {
		perror("create child process failed");
		goto fail;
	}

	container->exec.pid = pid;

	/* wait for ready message */
	if (hyper_get_type_block(arg.pipe[0], &type) < 0 || type != READY) {
		fprintf(stdout, "wait for container started failed\n");
		goto fail;
	}

	close(arg.pipe[0]);
	close(arg.pipe[1]);

	fprintf(stdout, "container %s init pid is %d\n", container->id, pid);
	return 0;

fail:
	fprintf(stdout, "container %s init exit code %d\n", container->id, -1);
	container->exec.code = -1;
	return -1;
}

int hyper_start_containers(struct hyper_pod *pod)
{
	int i;

	/* mount new proc directory */
	if (umount("/proc") < 0) {
		perror("umount proc filesystem failed\n");
		return -1;
	}

	if (mount("proc", "/proc", "proc", 0, NULL) < 0) {
		perror("mount proc filesystem failed\n");
		return -1;
	}

	if (sethostname(pod->hostname, strlen(pod->hostname)) < 0) {
		perror("set host name failed");
		return -1;
	}

	for (i = 0; i < pod->c_num; i++)
		hyper_start_container(&pod->c[i]);

	return 0;
}

int hyper_restart_containers(struct hyper_pod *pod)
{
	int i;
	struct hyper_container *c;

	for (i = 0; i < pod->c_num; i++) {
		c = &pod->c[i];

		if (hyper_start_container(c) < 0) {
			fprintf(stderr, "restart container %s failed\n", c->id);
			hyper_send_type(pod->ctl.fd, ERROR);
			return -1;
		}
	}

	if (hyper_send_type(pod->ctl.fd, ACK) < 0)
		return -1;

	return 0;
}

struct hyper_container *hyper_find_container(struct hyper_pod *pod, char *id)
{
	int i;
	struct hyper_container *container;

	for (i = 0; i < pod->c_num; i++) {
		container = &pod->c[i];

		if (strlen(container->id) != strlen(id))
			continue;

		if (strncmp(container->id, id, strlen(id)))
			continue;

		return container;
	}

	return NULL;
}

void hyper_cleanup_container(struct hyper_pod *pod)
{
	int i, j;
	struct hyper_container *c;
	struct volume *vol;
	struct env *env;
	struct fsmap *map;
	char root[512];

	for (i = 0; i < pod->c_num; i++) {
		c = &pod->c[i];

		sprintf(root, "/tmp/hyper/%s/devpts/", c->id);
		if (umount(root) < 0 && umount2(root, MNT_DETACH))
			perror("umount devpts failed");

		free(c->id);
		free(c->rootfs);
		free(c->image);
		free(c->workdir);
		free(c->fstype);

		for (j = 0; j < c->vols_num; j++) {
			vol = &(c->vols[j]);
			free(vol->device);
			free(vol->mountpoint);
			free(vol->fstype);
		}
		free(c->vols);

		for (j = 0; j < c->envs_num; j++) {
			env = &(c->envs[j]);
			free(env->env);
			free(env->value);
		}
		free(c->envs);

		for (j = 0; j < c->maps_num; j++) {
			map = &(c->maps[j]);
			free(map->source);
			free(map->path);
		}
		free(c->maps);
	}

	free(pod->c);
	pod->c = NULL;
	pod->c_num = 0;
}
