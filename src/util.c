#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <mntent.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <linux/reboot.h>

#include "net.h"
#include "util.h"

char *read_cmdline(void)
{
	return NULL;
}

int hyper_list_dir(char *path)
{
	struct dirent **list;
	struct dirent *dir;
	int i, num;

	fprintf(stdout, "list %s\n", path);
	num = scandir(path, &list, NULL, NULL);
	if (num < 0) {
		perror("scan path failed");
		return -1;
	}

	for (i = 0; i < num; i++) {
		dir = list[i];
		fprintf(stdout, "%s get %s\n", path, dir->d_name);
	}

	free(list);
	return 0;
}

int hyper_mkdir(char *hyper_path)
{
	struct stat st;
	char *p, *path = strdup(hyper_path);

	if (path == NULL) {
		errno = ENOMEM;
		return -1;
	}

	fprintf(stdout, "create directory %s\n", path);
	if (stat(path, &st) >= 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		errno = ENOTDIR;
		return -1;
	}

	if (errno != ENOENT)
		return -1;

	p = strrchr(path, '/');
	if (p == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (p != path) {
		*p = '\0';

		if (hyper_mkdir(path) < 0)
			return -1;

		*p = '/';
	}

	if (mkdir(path, 0755) < 0 && errno != EEXIST)
		return -1;

	return 0;
}

int hyper_open_channel(char *channel, int mode)
{
	struct dirent **list;
	struct dirent *dir;
	int fd = -1, i, num;
	char path[256], name[128];

	num = scandir("/sys/class/virtio-ports/", &list, NULL, NULL);
	if (num < 0) {
		perror("scan /sys/calss/virtio-ports/ failed");
		return -1;
	}

	memset(path, 0, sizeof(path));

	for (i = 0; i < num; i++) {
		dir = list[i];
		if (dir->d_name[0] == '.')
			continue;

		if (snprintf(path, sizeof(path), "/sys/class/virtio-ports/%s/name", dir->d_name) < 0) {
			fprintf(stderr, "get channel device %s path failed\n", dir->d_name);
			continue;
		}

		fd = open(path, O_RDONLY);

		memset(name, 0, sizeof(name));
		if (fd < 0 || read(fd, name, sizeof(name)) < 0)
			continue;

		close(fd);
		fd = -1;

		if (strncmp(name, channel, strlen(channel))) {
			fprintf(stderr, "channel %s, directory %s\n", channel, name);
			continue;
		}

		if (snprintf(path, sizeof(path), "/dev/%s", dir->d_name) < 0) {
			fprintf(stderr, "get channel device %s path failed\n", dir->d_name);
			continue;
		}

		fprintf(stdout, "open hyper channel %s\n", path);
		fd = open(path, O_RDWR | O_CLOEXEC | mode);
		if (fd < 0)
			perror("fail to open channel deice");

		break;
	}

	free(list);
	return fd;
}

int hyper_open_serial_dev(char *tty)
{
	int fd = open(tty, O_RDWR | O_CLOEXEC | O_NOCTTY);

	if (fd < 0) {
		perror("fail to open tty device");
		return -1;
	}

	return fd;
}

int hyper_open_serial(char *tty)
{
	char path[256];

	memset(path, 0, sizeof(path));

	if (snprintf(path, sizeof(path), "/dev/%s", tty) < 0) {
		fprintf(stderr, "get channel device %s path failed\n", tty);
		return -1;
	}

	fprintf(stdout, "open hyper tty %s\n", path);

	return hyper_open_serial_dev(path);
}

int hyper_setfd_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD);

	if (flags < 0) {
		perror("fcntl F_GETFD failed");
		return -1;
	}

	if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
		perror("fcntl F_SETFD failed");
		return -1;
	}

	return 0;
}

int hyper_setfd_block(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0) {
		perror("fcntl F_GETFL failed");
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
		perror("fcntl F_SETFD failed");
		return -1;
	}

	return 0;
}

int hyper_setfd_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0) {
		perror("fcntl F_GETFL failed");
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("fcntl F_SETFD failed");
		return -1;
	}

	return 0;
}

void hyper_unmount_all(void)
{
	FILE *mtab;
	struct mntent *mnt;
	char *mntlist[128];
	int i, n = 0;
	char *filesys;

	mtab = setmntent("/proc/mounts", "r");
	if (mtab == NULL) {
		fprintf(stderr, "cannot open /proc/mount");
		return;
	}

	while (n < 128) {
		mnt = getmntent(mtab);
		if (mnt == NULL)
			break;

		if (strcmp(mnt->mnt_type, "devtmpfs") == 0 ||
		    strcmp(mnt->mnt_type, "proc") == 0 ||
		    strcmp(mnt->mnt_type, "sysfs") == 0 ||
		    strcmp(mnt->mnt_type, "ramfs") == 0 ||
		    strcmp(mnt->mnt_type, "tmpfs") == 0 ||
		    strcmp(mnt->mnt_type, "rootfs") == 0 ||
		    strcmp(mnt->mnt_type, "devpts") == 0)
			continue;

		mntlist[n++] = strdup(mnt->mnt_dir);
	}

	endmntent(mtab);

	for (i = n - 1; i >= 0; i--) {
		filesys = mntlist[i];
		fprintf(stdout, "umount %s\n", filesys);
		if ((umount(mntlist[i]) < 0) && (umount2(mntlist[i], MNT_DETACH) < 0)) {
			fprintf(stdout, ("umount %s: %s failed\n"),
				filesys, strerror(errno));
		}
	}

	sync();
}

void hyper_kill_all(void)
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
}

void hyper_shutdown(struct hyper_pod *pod)
{
	int i;
	uint8_t *data = calloc(pod->c_num, 4);

	for (i = 0; i < pod->c_num; i++)
		hyper_set_be32(data + (i * 4), pod->c[i].exec.code);

	hyper_send_msg(ctl.chan.fd, FINISH, pod->c_num * 4, data);

	hyper_unmount_all();
	hyper_kill_all();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
}
