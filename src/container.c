#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
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
			fprintf(stderr, "the _data in volume %s is not directory\n", dest);
			return -1;
		}

		return 0;
	}

	if (errno != ENOENT) {
		perror("access to volume failed\n");
		return -1;
	}

	if (hyper_mkdir(dest, 0777) < 0) {
		fprintf(stderr, "fail to create directory %s\n", dest);
		return -1;
	}

	return hyper_copy_dir(src, dest);
}

const char *INIT_VOLUME_FILENAME = ".hyper_file_volume_data_do_not_create_on_your_own";

static int container_check_file_volume(char *hyper_path, const char **filename)
{
	struct dirent **list;
	struct stat stbuf;
	int i, num, found = 0;
	char path[PATH_MAX];

	*filename = NULL;
	num = scandir(hyper_path, &list, NULL, NULL);
	if (num < 0) {
		/* No data in the volume yet, treat as non-file-volume */
		if (errno == ENOENT) {
			return 0;
		}
		perror("scan path failed");
		return -1;
	} else if (num != 3) {
		fprintf(stdout, "%s has %d files/dirs\n", hyper_path, num - 2);
		for (i = 0; i < num; i++) {
			free(list[i]);
		}
		free(list);
		return 0;
	}

	sprintf(path, "%s/%s", hyper_path, INIT_VOLUME_FILENAME);
	for (i = 0; i < num; i++) {
		if (strcmp(list[i]->d_name, ".") != 0 &&
		    strcmp(list[i]->d_name, "..") != 0 &&
		    strcmp(list[i]->d_name, INIT_VOLUME_FILENAME) == 0 &&
		    stat(path, &stbuf) == 0 && S_ISREG(stbuf.st_mode)) {
			found++;
		}
		free(list[i]);
	}
	free(list);

	fprintf(stdout, "%s %s a file volume\n", hyper_path, found > 0?"is":"is not");
	*filename = found > 0 ? INIT_VOLUME_FILENAME : NULL;
	return 0;
}

static int container_setup_volume(struct hyper_container *container)
{
	int i;
	char dev[512], path[512];
	struct volume *vol;

	for (i = 0; i < container->vols_num; i++) {
		char volume[512];
		char mountpoint[512];
		char *options = NULL;
		const char *filevolume = NULL;
		vol = &container->vols[i];

		if (vol->scsiaddr)
			hyper_find_sd(vol->scsiaddr, &vol->device);

		sprintf(dev, "/dev/%s", vol->device);
		sprintf(path, "/tmp/%s", vol->mountpoint);
		sprintf(mountpoint, "./%s", vol->mountpoint);

		if (hyper_mkdir(path, 0755) < 0) {
			perror("create volume dir failed");
			return -1;
		}

		if (!strcmp(vol->fstype, "nfs")) {
			fprintf(stdout, "mount nfs share %s to %s, tmp path %s\n",
				vol->device, vol->mountpoint, path);

			if (hyper_mount_nfs(vol->device, path) < 0)
				return -1;
			/* nfs export has implicitly included _data part of the volume */
			sprintf(volume, "/%s/", path);
		} else {
			fprintf(stdout, "mount %s to %s, tmp path %s\n",
				dev, vol->mountpoint, path);

			if (!strcmp(vol->fstype, "xfs"))
				options = "nouuid";

			if (mount(dev, path, vol->fstype, 0, options) < 0) {
				perror("mount volume device failed");
				return -1;
			}
			sprintf(volume, "/%s/_data", path);
		}

		if (container_check_file_volume(volume, &filevolume) < 0)
			return -1;

		if (filevolume == NULL) {
			if (hyper_mkdir(mountpoint, 0755) < 0) {
				perror("create volume dir failed");
				return -1;
			}
			if (vol->docker) {
				if (container->initialize &&
				    (container_populate_volume(mountpoint, volume) < 0)) {
					fprintf(stderr, "fail to populate volume %s\n", mountpoint);
					return -1;
				}
			} else if (hyper_mkdir(volume, 0777) < 0) {
				/* First time mounting an empty volume */
				perror("create _data dir failed");
				return -1;
			}
		} else {
			hyper_filize(mountpoint);
			if (hyper_create_file(mountpoint) < 0) {
				perror("create volume file failed");
				return -1;
			}
			sprintf(volume, "/%s/_data/%s", path, filevolume);
			/* 0777 so that any user can read/write the new file volume */
			if (chmod(volume, 0777) < 0) {
				fprintf(stderr, "fail to chmod directory %s\n", volume);
				return -1;
			}
		}

		if (mount(volume, mountpoint, NULL, MS_BIND, NULL) < 0) {
			perror("mount volume device failed");
			return -1;
		}

		if (vol->readonly &&
		    mount(volume, mountpoint, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
			perror("mount fsmap failed");
			return -1;
		}

		umount(path);
	}

	for (i = 0; i < container->maps_num; i++) {
		struct stat st;
		char *src, path[512], volume[512];
		struct fsmap *map = &container->maps[i];
		char mountpoint[512];

		sprintf(path, "%s/%s", SHARED_DIR, map->source);
		sprintf(mountpoint, "./%s", map->path);
		fprintf(stdout, "mount %s to %s\n", path, mountpoint);

		src = path;
		stat(src, &st);

		if (st.st_mode & S_IFDIR) {
			if (hyper_mkdir(mountpoint, 0755) < 0) {
				perror("create map dir failed");
				continue;
			}
			if (map->docker) {
				/* converted from volume */
				sprintf(volume, "%s/_data", path);
				src = volume;
				if (container->initialize &&
				    (container_populate_volume(mountpoint, volume) < 0)) {
					fprintf(stderr, "fail to populate volume %s\n", mountpoint);
					continue;
				}
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
			perror("mount fsmap failed");
			continue;
		}

		if (map->readonly == 0)
			continue;

		if (mount(src, mountpoint, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0)
			perror("mount fsmap failed");
	}

	return 0;
}

static int container_setup_modules(struct hyper_container *container)
{
	struct stat st;
	struct utsname uts;
	char src[512], dst[512];

	if (uname(&uts) < 0) {
		perror("fail to call uname");
		return -1;
	}

	sprintf(src, "/lib/modules/%s", uts.release);
	sprintf(dst, "./%s", src);

	if (stat(dst, &st) == 0) {
		struct dirent **list;
		int num;

		if (!S_ISDIR(st.st_mode)) {
			return -1;
		}

		num = scandir(dst, &list, NULL, NULL);
		if (num > 2) {
			fprintf(stdout, "%s is not null, %d", dst, num);
			return 0;
		}
	} else if (errno == ENOENT) {
		if (hyper_mkdir(dst, 0755) < 0)
			return -1;
	} else {
		return -1;
	}

	if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
		perror("mount bind modules failed");
		return -1;
	}

	return 0;
}

static int container_setup_mount(struct hyper_container *container)
{
	char src[512];

	// current dir is container rootfs, the operations on "./PATH" are the operations on container's "/PATH"
	hyper_mkdir("./proc", 0755);
	hyper_mkdir("./sys", 0755);
	hyper_mkdir("./dev", 0755);
	hyper_mkdir("./lib/modules", 0755);

	if (mount("proc", "./proc", "proc", MS_NOSUID| MS_NODEV| MS_NOEXEC, NULL) < 0 ||
	    mount("sysfs", "./sys", "sysfs", MS_NOSUID| MS_NODEV| MS_NOEXEC, NULL) < 0 ||
	    mount("devtmpfs", "./dev", "devtmpfs", MS_NOSUID, NULL) < 0) {
		perror("mount basic filesystem for container failed");
		return -1;
	}

	if (hyper_mkdir("./dev/shm", 0755) < 0) {
		fprintf(stderr, "create /dev/shm failed\n");
		return -1;
	}

	if (mount("tmpfs", "./dev/shm/", "tmpfs", MS_NOSUID| MS_NODEV, NULL) < 0) {
		perror("mount shm failed");
		return -1;
	}

	if (hyper_mkdir("./dev/pts", 0755) < 0) {
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

	/* all containers share the same devtmpfs, so we need to ignore the errno EEXIST */
	if (symlink("/dev/pts/ptmx", "./dev/ptmx") < 0 && errno != EEXIST) {
		perror("link /dev/pts/ptmx to /dev/ptmx failed");
		return -1;
	}

	if ((symlink("/proc/self/fd", "./dev/fd") < 0 && errno != EEXIST) ||
	    (symlink("/proc/self/fd/0", "./dev/stdin") < 0 && errno != EEXIST) ||
	    (symlink("/proc/self/fd/1", "./dev/stdout") < 0 && errno != EEXIST) ||
	    (symlink("/proc/self/fd/2", "./dev/stderr") < 0 && errno != EEXIST)) {
		perror("failed to symlink for /dev/fd, /dev/stdin, /dev/stdout or /dev/stderr");
		return -1;
	}

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

	hyper_mkdir("./etc/", 0755);

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
	int i;
	struct sysctl *sys;

	for (i = 0; i < container->sys_num; i++) {
		char path[256];

		sys = &container->sys[i];

		sprintf(path, "/proc/sys/%s", sys->path);
		fprintf(stdout, "sysctl %s value %s\n", sys->path, sys->value);

		if (hyper_write_file(path, sys->value, strlen(sys->value)) < 0) {
			fprintf(stderr, "sysctl: write %s to %s failed\n", sys->value, path);
			return -1;
		}
	}

	return 0;
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

	hyper_mkdir("./etc", 0755);

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
		return hyper_mkdir(container->exec.workdir, 0755);
	}

	return 0;
}

static int hyper_rescan_scsi(void)
{
	struct dirent **list;
	struct dirent *dir;
	int fd = -1, i, num;
	char path[256];

	num = scandir("/sys/class/scsi_host/", &list, NULL, NULL);
	if (num < 0) {
		perror("scan /sys/class/scsi_host/ failed");
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
	int			pipe[2];
	int			pipens[2];
};

static int hyper_setup_container_rootfs(void *data)
{
	struct hyper_container_arg *arg = data;
	struct hyper_container *container = arg->c;
	char root[512], rootfs[512];
	int setup_dns;
	uint32_t type;

	/* wait for ns-opened ready message */
	if (hyper_get_type(arg->pipens[0], &type) < 0 || type != READY) {
		fprintf(stderr, "wait for /proc/self/ns/mnt opened failed\n");
		goto fail;
	}

	if (hyper_enter_sandbox(arg->pod, -1) < 0) {
		perror("enter sandbox failed");
		goto fail;
	}

	/* To create files/directories accessible for all users. */
	umask(0);

	if (container->fstype && hyper_rescan_scsi() < 0) {
		fprintf(stdout, "rescan scsi failed\n");
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
	if (hyper_mkdir(root, 0755) < 0) {
		perror("make root directory failed");
		goto fail;
	}

	if (container->fstype) {
		char dev[128];
		char *options = NULL;

		if (container->scsiaddr) {
			free(container->image);
			container->image = NULL;
			hyper_find_sd(container->scsiaddr, &container->image);
		}

		sprintf(dev, "/dev/%s", container->image);
		fprintf(stdout, "device %s\n", dev);

		if (!strncmp(container->fstype, "xfs", strlen("xfs")))
			options = "nouuid";

		if (mount(dev, root, container->fstype, 0, options) < 0) {
			perror("mount device failed");
			goto fail;
		}
	} else {
		char path[512];

		sprintf(path, "%s/%s/", SHARED_DIR, container->image);
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
	if (chdir(rootfs) < 0) {
		perror("failed to change the root to path of the container root(before manipulating)");
		goto fail;
	}

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

	// ignore error of setup modules
	container_setup_modules(container);

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
	if (chroot(".") < 0) {
		perror("failed to setup the root for the mount namepsace");
		goto fail;
	}

	if (chdir("/") < 0) {
		perror("failed chdir to the new root");
		goto fail;
	}

	if (container_setup_sysctl(container) < 0) {
		fprintf(stderr, "container sets up sysctl failed\n");
		goto fail;
	}

	if (container_setup_workdir(container) < 0) {
		fprintf(stderr, "container sets up work directory failed\n");
		goto fail;
	}

	hyper_send_type(arg->pipe[1], READY);
	fflush(NULL);
	_exit(0);

fail:
	hyper_send_type(arg->pipe[1], ERROR);
	_exit(125);
}

static int hyper_setup_pty(struct hyper_container *c)
{
	char root[512];

	sprintf(root, "/tmp/hyper/%s/devpts/", c->id);

	if (hyper_mkdir(root, 0755) < 0) {
		perror("make container pts directory failed");
		return -1;
	}

	if (mount("devpts", root, "devpts", MS_NOSUID,
		  "newinstance,ptmxmode=0666,mode=0620") < 0) {
		perror("mount devpts failed");
		return -1;
	}

	return 0;
}

int hyper_setup_container(struct hyper_container *container, struct hyper_pod *pod)
{
	int stacksize = getpagesize() * 42;
	struct hyper_container_arg arg = {
		.c	= container,
		.pod	= pod,
		.pipe	= {-1, -1},
		.pipens = {-1, -1},
	};
	int flags = CLONE_NEWNS | SIGCHLD;
	char path[128];
	void *stack;
	uint32_t type;
	int pid;

	container->exec.pod = pod;

	if (pipe2(arg.pipe, O_CLOEXEC) < 0 || pipe2(arg.pipens, O_CLOEXEC) < 0) {
		perror("create pipe between pod init execcmd failed");
		goto fail;
	}

	if (hyper_setup_container_portmapping(container, pod) < 0) {
		perror("fail to setup port mapping for container");
		goto fail;
	}

	if (hyper_setup_pty(container) < 0) {
		fprintf(stderr, "setup pty device for container failed\n");
		goto fail;
	}

	stack = malloc(stacksize);
	if (stack == NULL) {
		perror("fail to allocate stack for container init");
		goto fail;
	}

	pid = clone(hyper_setup_container_rootfs, stack + stacksize, flags, &arg);
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
	hyper_send_type(arg.pipens[1], READY);

	/* wait for ready message */
	if (hyper_get_type(arg.pipe[0], &type) < 0 || type != READY) {
		fprintf(stderr, "wait for setup container rootfs failed\n");
		goto fail;
	}

	close(arg.pipe[0]);
	close(arg.pipe[1]);
	close(arg.pipens[0]);
	close(arg.pipens[1]);
	return 0;
fail:
	close(container->ns);
	container->ns = -1;
	close(arg.pipe[0]);
	close(arg.pipe[1]);
	close(arg.pipens[0]);
	close(arg.pipens[1]);
	return -1;
}

struct hyper_container *hyper_find_container(struct hyper_pod *pod, const char *id)
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

void hyper_cleanup_container(struct hyper_container *c, struct hyper_pod *pod)
{
	char root[512];

	sprintf(root, "/tmp/hyper/%s/devpts/", c->id);
	if (umount(root) < 0 && umount2(root, MNT_DETACH))
		perror("umount devpts failed");

	close(c->ns);
	hyper_cleanup_container_portmapping(c, pod);
	hyper_free_container(c);
}

void hyper_cleanup_containers(struct hyper_pod *pod)
{
	struct hyper_container *c, *n;

	list_for_each_entry_safe(c, n, &pod->containers, list)
		hyper_cleanup_container(c, pod);

	pod->remains = 0;
}
