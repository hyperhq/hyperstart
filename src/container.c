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
#include <sys/eventfd.h>

#include "util.h"
#include "hyper.h"
#include "parse.h"
#include "syscall.h"
#include "netlink.h"

static int container_populate_volume(char *src, char *dest)
{
	struct stat st;

	fprintf(stdout, "populate volumes from %s to %s\n", src, dest);

	if (stat(dest, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "the _data in volume %s is not directory\n", dest);
			return -1;
		}
	} else if (errno != ENOENT) {
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

const char *LOST_AND_FOUND_DIR = "lost+found";

static int container_check_volume(char *hyper_path, const char **filename, bool *newvolume)
{
	struct dirent **list;
	struct stat stbuf;
	int i, num, found = 0;
	char path[PATH_MAX];

	*filename = NULL;
	*newvolume = false;
	num = scandir(hyper_path, &list, NULL, NULL);
	if (num < 0) {
		/* No data in the volume yet, treat as new volume */
		if (errno == ENOENT) {
			*newvolume = true;
			goto out;
		}
		perror("scan path failed");
		return -1;
	} else if (num == 2) {
		*newvolume = true;
	} else if (num > 3) {
		fprintf(stdout, "%s has %d files/dirs\n", hyper_path, num - 2);
		for (i = 0; i < num; i++) {
			free(list[i]);
		}
		free(list);
		return 0;
	}

	/* num is either 2 or 3 */
	for (i = 0; i < num; i++) {
		if (strcmp(list[i]->d_name, ".") == 0 ||
		    strcmp(list[i]->d_name, "..") == 0) {
			free(list[i]);
			continue;
		}

		if (strcmp(list[i]->d_name, INIT_VOLUME_FILENAME) == 0) {
			sprintf(path, "%s/%s", hyper_path, INIT_VOLUME_FILENAME);
			if (stat(path, &stbuf) == 0 && S_ISREG(stbuf.st_mode))
				found++;
		} else if (strcmp(list[i]->d_name, LOST_AND_FOUND_DIR) == 0) {
			sprintf(path, "%s/%s", hyper_path, LOST_AND_FOUND_DIR);
			if (stat(path, &stbuf) == 0 && S_ISDIR(stbuf.st_mode) &&
			    hyper_empty_dir(path)) {
				*newvolume = true;
			}
		}
		free(list[i]);
	}
	free(list);

out:
	if (found > 0) {
		*filename = INIT_VOLUME_FILENAME;
		fprintf(stdout, "%s is a file volume\n", hyper_path);
	} else if (*newvolume) {
		fprintf(stdout, "%s is a new volume\n", hyper_path);
	}
	return 0;
}

static int container_setup_volume(struct hyper_pod *pod,
				  struct hyper_container *container)
{
	int i;
	char dev[512], path[512];
	struct volume *vol;

	for (i = 0; i < container->vols_num; i++) {
		char volume[512];
		char mountpoint[512];
		char *options = NULL;
		const char *filevolume = NULL;
		bool newvolume = false;
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

			if (access(dev, R_OK) < 0) {
				char device[512];
				sprintf(device, "/block/%s", vol->device);
				hyper_netlink_wait_dev(pod->ueventfd, device);
			}

			if (mount(dev, path, vol->fstype, 0, options) < 0) {
				perror("mount volume device failed");
				return -1;
			}
			sprintf(volume, "/%s/_data", path);
		}

		if (container_check_volume(volume, &filevolume, &newvolume) < 0)
			return -1;

		if (filevolume == NULL) {
			if (hyper_mkdir_at(".", mountpoint, sizeof(mountpoint)) < 0) {
				perror("create map dir failed");
				return -1;
			}
			fprintf(stdout, "docker vol %d initialize %d newvolume %d\n",
					vol->docker, container->initialize, newvolume);
			if (vol->docker) {
				if (container->initialize && newvolume &&
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
			if (hyper_create_file_at(".", mountpoint, sizeof(mountpoint)) < 0) {
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
			perror("mount volume ro failed");
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
			if (hyper_mkdir_at(".", mountpoint, sizeof(mountpoint)) < 0) {
				perror("create map dir failed");
				return -1;
			}
			if (map->docker) {
				/* converted from volume */
				sprintf(volume, "%s/_data", path);
				src = volume;
				if (container->initialize &&
				    (container_populate_volume(mountpoint, volume) < 0)) {
					fprintf(stderr, "fail to populate volume %s\n", mountpoint);
					return -1;
				}
			}
		} else {
			if (hyper_create_file_at(".", mountpoint, sizeof(mountpoint)) < 0) {
				perror("create volume file failed");
				return -1;
			}
		}

		if (mount(src, mountpoint, NULL, MS_BIND, NULL) < 0) {
			perror("mount fsmap failed");
			return -1;
		}

		if (map->readonly == 0)
			continue;

		if (mount(src, mountpoint, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
			perror("mount fsmap ro failed");
			return -1;
		}
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
		int i;

		if (!S_ISDIR(st.st_mode)) {
			return -1;
		}

		num = scandir(dst, &list, NULL, NULL);
		if (num > 1) {
			for (i = 0; i < num; i++) {
				free(list[i]);
			}
			free(list);
		}
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
	if (!container->readonly) {
		hyper_mkdir("./proc", 0755);
		hyper_mkdir("./sys", 0755);
		hyper_mkdir("./dev", 0755);
		hyper_mkdir("./lib/modules", 0755);

	}

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

	if (mount("/tmp/hyper/shm", "./dev/shm/", "tmpfs", MS_BIND, NULL) < 0) {
		perror("bind mount shared shm failed");
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
	if (!container->initialize || container->readonly)
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

static int container_binding_file(char *src, char *dest)
{
	int fd;
	struct stat st;

	if (stat(src, &st) < 0) {
		if (errno == ENOENT) {
			fprintf(stdout, "can not find %s\n", src);
			return 0;
		}

		fprintf(stderr, "stat %s failed: %s\n", src, strerror(errno));
		return -1;
	}

	if (stat(dest, &st) < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "stat %s failed: %s\n", dest, strerror(errno));
			return 0;
		}
		fprintf(stdout, "can not find %s\n", dest);
		fd = open(dest, O_CREAT| O_WRONLY, 0644);
		if (fd < 0) {
			// root filesystem may be read only, don't fail
			fprintf(stderr, "create %s failed: %s\n", dest, strerror(errno));
			return 0;
		}
		close(fd);
	}

	if (mount(src, dest, NULL, MS_BIND, NULL) < 0) {
		fprintf(stderr, "bind to %s failed: %s\n", dest, strerror(errno));
		return -1;
	}

	return 0;
}

static int container_setup_dns()
{
	hyper_mkdir("./etc", 0755);
	return container_binding_file("/tmp/hyper/resolv.conf", "./etc/resolv.conf");
}

static int container_setup_hostname()
{
	hyper_mkdir("./etc", 0755);
	return container_binding_file("/tmp/hyper/hostname", "./etc/hostname");
}

static int container_setup_workdir(struct hyper_container *container)
{
	if (container->initialize && !container->readonly) {
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
	for (i = 0; i < num; i++) {
		free(list[i]);
	}
	free(list);
	return 0;
}

struct hyper_container_arg {
	struct hyper_container	*c;
	struct hyper_pod	*pod;
	int			mntns_referenced_efd;
	int			container_inited_efd;
	int			container_root_dev_efd;
};

static int hyper_setup_container_rootfs(void *data)
{
	struct hyper_container_arg *arg = data;
	struct hyper_container *container = arg->c;
	char root[512], rootfs[512];
	int setup_dns;

	/* wait for ns-opened ready message */
	if (hyper_eventfd_recv(arg->mntns_referenced_efd) < 0) {
		fprintf(stderr, "wait for /proc/self/ns/mnt opened failed\n");
		goto fail;
	}

	if (hyper_enter_sandbox(arg->pod, -1) < 0) {
		perror("enter sandbox failed");
		goto fail;
	}

	/* To create files/directories accessible for all users. */
	umask(0);

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
		unsigned long flags = 0;

		/* wait for rootfs ready message */
		if (hyper_eventfd_recv(arg->container_root_dev_efd) < 0) {
			fprintf(stderr, "wait for /proc/self/ns/mnt opened failed\n");
			goto fail;
		}

		if (container->scsiaddr) {
			free(container->image);
			container->image = NULL;
			hyper_find_sd(container->scsiaddr, &container->image);
		}
		sprintf(dev, "/dev/%s", container->image);
		fprintf(stdout, "device %s\n", dev);

		if (container->readonly)
			flags = MS_RDONLY;

		if (!strncmp(container->fstype, "xfs", strlen("xfs")))
			options = "nouuid";

		if (mount(dev, root, container->fstype, flags, options) < 0) {
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
		if (container->readonly && mount(NULL, root, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0) {
			perror("mount src dir readonly failed");
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

	if (container_setup_volume(arg->pod, container) < 0) {
		fprintf(stderr, "container sets up voulme failed\n");
		goto fail;
	}

	if (container_setup_dns() < 0) {
		fprintf(stderr, "container sets up dns failed\n");
		goto fail;
	}

	if (container_setup_hostname() < 0) {
		fprintf(stderr, "container sets up hostname failed\n");
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

	fprintf(stdout, "hyper send container inited event: normal\n");
	hyper_eventfd_send(arg->container_inited_efd, HYPER_EVENTFD_NORMAL);
	fflush(NULL);
	_exit(0);

fail:
	fprintf(stderr, "hyper send container inited event: error\n");
	hyper_eventfd_send(arg->container_inited_efd, HYPER_EVENTFD_ERROR);
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

static void hyper_cleanup_pty(struct hyper_container *c)
{
	char path[512];

	sprintf(path, "/tmp/hyper/%s/devpts/", c->id);
	if (umount(path) < 0)
		perror("clean up container pty failed");
}

int container_prepare_rootfs_dev(struct hyper_container *container, struct hyper_pod *pod)
{
	char dev[512];

	if (container->fstype == NULL)
		return 0;

	if (hyper_rescan_scsi() < 0) {
		fprintf(stderr, "failed to issue scsi rescan\n");
		return -1;
	}

	if (container->scsiaddr) {
		free(container->image);
		container->image = NULL;
		hyper_find_sd(container->scsiaddr, &container->image);
	}

	if (container->image) {
		sprintf(dev, "/dev/%s", container->image);
		if (access(dev, R_OK) == 0)
			return 0;
		sprintf(dev, "/block/%s", container->image);
	} else {
		sprintf(dev, "/0:0:%s/block/", container->scsiaddr);
	}

	return hyper_netlink_wait_dev(pod->ueventfd, dev);
}

int hyper_setup_container(struct hyper_container *container, struct hyper_pod *pod)
{
	int stacksize = getpagesize() * 42;
	struct hyper_container_arg arg = {
		.c	= container,
		.pod	= pod,
		.mntns_referenced_efd	= -1,
		.container_inited_efd 	= -1,
		.container_root_dev_efd = -1,
	};
	int flags = CLONE_NEWNS | SIGCHLD;
	char path[128];
	void *stack;
	int pid;

	container->exec.pod = pod;

	arg.mntns_referenced_efd = eventfd(0, EFD_CLOEXEC);
	arg.container_inited_efd = eventfd(0, EFD_CLOEXEC);
	arg.container_root_dev_efd = eventfd(0, EFD_CLOEXEC);
	if (arg.mntns_referenced_efd < 0 || arg.container_inited_efd < 0 ||
	    arg.container_root_dev_efd < 0) {
		perror("create eventfd between pod init execcmd failed");
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
	fprintf(stdout, "hyper send mntns referenced event: normal\n");
	hyper_eventfd_send(arg.mntns_referenced_efd, HYPER_EVENTFD_NORMAL);

	if (container_prepare_rootfs_dev(container, pod) < 0) {
		fprintf(stderr, "fail to prepare container rootfs dev\n");
		goto fail;
	}
	fprintf(stdout, "hyper send root dev ready event: normal\n");
	hyper_eventfd_send(arg.container_root_dev_efd, HYPER_EVENTFD_NORMAL);

	/* wait for ready message */
	if (hyper_eventfd_recv(arg.container_inited_efd) < 0) {
		fprintf(stderr, "wait for setup container rootfs failed\n");
		goto fail;
	}

	close(arg.mntns_referenced_efd);
	close(arg.container_inited_efd);
	close(arg.container_root_dev_efd);
	return 0;
fail:
	close(container->ns);
	container->ns = -1;
	close(arg.mntns_referenced_efd);
	close(arg.container_inited_efd);
	close(arg.container_root_dev_efd);
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

static void hyper_cleanup_container_mounts(struct hyper_container *container, struct hyper_pod *pod)
{
	int pid, efd = -1;

	efd = eventfd(0, EFD_CLOEXEC);
	if (efd < 0) {
		perror("create eventfd for unmount failed");
		return;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork unmount process failed");
		goto out;
	} else if (pid == 0) {
		if (hyper_enter_sandbox(pod, -1) < 0) {
			fprintf(stderr, "hyper send enter sandbox event: error\n");
			hyper_eventfd_send(efd, HYPER_EVENTFD_ERROR);
			_exit(-1);
		}
		if (setns(container->ns, CLONE_NEWNS) < 0) {
			perror("fail to enter container ns");
			fprintf(stderr, "hyper send enter container ns event: error\n");
			hyper_eventfd_send(efd, HYPER_EVENTFD_ERROR);
			_exit(-1);
		}
		hyper_unmount_all();
		fprintf(stdout, "hyper send cleanup container mounts event: normal\n");
		hyper_eventfd_send(efd, HYPER_EVENTFD_NORMAL);
		_exit(0);
	}
	hyper_eventfd_recv(efd);

out:
	close(efd);
}

void hyper_cleanup_container(struct hyper_container *c, struct hyper_pod *pod)
{
	hyper_cleanup_container_mounts(c, pod);
	close(c->ns);
	hyper_cleanup_pty(c);
	hyper_cleanup_container_portmapping(c, pod);
	hyper_free_container(c);
}

void hyper_cleanup_mounts(struct hyper_pod *pod)
{
	struct hyper_container *c;

	list_for_each_entry(c, &pod->containers, list)
		hyper_cleanup_container_mounts(c, pod);
}
