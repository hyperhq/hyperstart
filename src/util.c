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
#include <unistd.h>
#include <mntent.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/reboot.h>
#include <linux/reboot.h>

#include "util.h"
#include "hyper.h"
#include "container.h"
#include "../config.h"

char *read_cmdline(void)
{
	return NULL;
}

int hyper_setup_env(struct env *envs, int num)
{
	int i, ret = 0;
	struct env *env;

	for (i = 0; i < num; i++) {
		env = &envs[i];
		if (setenv(env->env, env->value, 1) < 0) {
			perror("fail to setup env");
			ret = -1;
		}
	}

	return ret;
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
		free(dir);
	}

	free(list);
	return 0;
}

int hyper_copy_dir(char *src, char *dest) {
	int pid, status;

	pid = fork();
	if (pid < 0) {
		perror("fail to fork to copy directory");
		return -1;
	} else if (pid > 0) {
		if (waitpid(pid, &status, 0) <= 0) {
			perror("waiting copy directroy finish failed");
			return -1;
		}
		if (WIFEXITED(status)) {
			int ret = WEXITSTATUS(status);
			fprintf(stdout, "copy directroy exit normally, status %" PRIu8 "\n", ret);
			if (ret == 0)
				return 0;
		}

		fprintf(stderr, "copy directroy exit unexpectedly, status %" PRIu8 "\n", status);
		return -1;
	} else {
		char cmd[512];
		snprintf(cmd, sizeof(cmd), "/tar cf - -C %s . | /tar fx - -C %s", src, dest);
		fprintf(stdout, "command for copy is %s\n", cmd);

		execlp("/busybox", "sh", "-c", cmd, NULL);
		perror("exec copy directroy command failed");
	}

	return -1;
}

void hyper_sync_time_hctosys() {
	int pid;
	pid = fork();
	if (pid < 0) {
		perror("fail to fork to copy directory");
	} else if (pid == 0) {
		execlp("/busybox", "hwclock", "-s", NULL);
		perror("exec hwclock -s command failed");
		exit(-1);
	}
}

int hyper_find_sd(char *addr, char **dev)
{
	struct dirent **list;
	struct dirent *dir;
	char path[512];
	int i, num;

	sprintf(path, "/sys/class/scsi_disk/0:0:%s/device/block/", addr);
	fprintf(stdout, "orig dev %s, scan path %s\n", *dev, path);

	num = scandir(path, &list, NULL, NULL);
	if (num < 0) {
		perror("scan path failed");
		return -1;
	}

	for (i = 0; i < num; i++) {
		dir = list[i];
		if (dir->d_name[0] == '.') {
			continue;
		}

		fprintf(stdout, "%s get %s\n", path, dir->d_name);
		*dev = strdup(dir->d_name);
		break;
	}

	for (i = 0; i < num; i++)
		free(list[i]);

	free(list);
	return 0;
}

int hyper_mkdir(char *hyper_path)
{
	struct stat st;
	char *p, *path = strdup(hyper_path);

	if (path == NULL) {
		errno = ENOMEM;
		goto fail;
	}

	if (stat(path, &st) >= 0) {
		if (S_ISDIR(st.st_mode))
			goto out;
		errno = ENOTDIR;
		goto fail;
	}

	if (errno != ENOENT)
		goto fail;

	p = strrchr(path, '/');
	if (p == NULL) {
		errno = EINVAL;
		goto fail;
	}

	if (p != path) {
		*p = '\0';

		if (hyper_mkdir(path) < 0)
			goto fail;

		*p = '/';
	}

	fprintf(stdout, "create directory %s\n", path);
	if (mkdir(path, 0755) < 0 && errno != EEXIST) {
		perror("failed to create directory");
		goto fail;
	}
out:
	free(path);
	return 0;

fail:
	free(path);
	return -1;
}

void online_cpu(void)
{
	DIR *dir = opendir("/sys/devices/system/cpu");
	if (dir == NULL) {
		fprintf(stderr, "open dir /sys/devices/system/cpu failed\n");
		return;
	}
	printf("online_cpu()\n");
	for (;;) {
		int num;
		int ret;
		char path[256];
		int fd;

		struct dirent *entry = readdir(dir);
		if (entry == NULL)
			break;
		if (entry->d_type != DT_DIR)
			continue;
		ret = sscanf(entry->d_name, "cpu%d", &num);
		if (ret < 1 || num == 0) /* skip none cpu%d and cpu0 */
			continue;
		sprintf(path, "/sys/devices/system/cpu/%s/online", entry->d_name);
		fd = open(path, O_RDWR);
		if (fd < 0) {
			fprintf(stderr, "open %s failed\n", path);
			continue;
		}
		printf("try to online %s\n", entry->d_name);
		ret = write(fd, "1", sizeof("1"));
		printf("online %s result: %s\n", entry->d_name, ret == 2 ? "success" : "failed");
		close(fd);
	}
	closedir(dir);
}

void online_memory(void)
{
	DIR *dir = opendir("/sys/devices/system/memory");
	if (dir == NULL) {
		fprintf(stderr, "open dir /sys/devices/system/memory failed\n");
		return;
	}
	printf("online_memory()\n");
	for (;;) {
		int num;
		int ret;
		char path[256];
		int fd;

		struct dirent *entry = readdir(dir);
		if (entry == NULL)
			break;
		if (entry->d_type != DT_DIR)
			continue;
		ret = sscanf(entry->d_name, "memory%d", &num);
		if (ret < 1 || num == 0) /* skip none memory%d and memory0 */
			continue;
		sprintf(path, "/sys/devices/system/memory/%s/online", entry->d_name);
		fd = open(path, O_RDWR);
		if (fd < 0) {
			fprintf(stderr, "open %s failed\n", path);
			continue;
		}
		printf("try to online %s\n", entry->d_name);
		ret = write(fd, "1", sizeof("1"));
		printf("online %s result: %s\n", entry->d_name, ret == 2 ? "success" : "failed");
		close(fd);
	}
	closedir(dir);
}

#if WITH_VBOX

#include <termios.h>
int hyper_open_channel(char *channel, int mode)
{
	struct termios term;
	int fd = open(channel, O_RDWR | O_CLOEXEC | mode);
	fprintf(stdout, "open %s get %d\n", channel, fd);

	if (fd < 0) {
		perror("fail to open channel device");
		return -1;
	}

	bzero(&term, sizeof(term));

	cfmakeraw(&term);
	term.c_cflag |= CLOCAL | CREAD| CRTSCTS;
	term.c_cc[VTIME] = 0;
	term.c_cc[VMIN] = 0;

	cfsetispeed(&term, B115200);
	cfsetospeed(&term, B115200);

	tcsetattr(fd, TCSANOW, &term);

	return fd;
}

static const char *moderror(int err)
{
	switch (err) {
	case ENOEXEC:
		return "Invalid module format";
	case ENOENT:
		return "Unknown symbol in module";
	case ESRCH:
		return "Module has wrong symbol version";
	case EINVAL:
		return "Invalid parameters";
	default:
		return strerror(err);
	}
}

extern long init_module (void *, unsigned long, const char *);

int hyper_insmod(char *module)
{
	size_t size, offset = 0, rc;
	struct stat st;
	char *buf = NULL;
	int ret;

	int fd = open(module, O_RDONLY);
	if (fd == -1) {
		fprintf (stderr, "insmod: open: %s: %m\n", module);
		return -1;
	}

	if (fstat(fd, &st) == -1) {
		perror ("insmod: fstat");
		goto err;
	}

	size = st.st_size;
	buf = malloc(size);
	if (buf == NULL)
		goto err;

	do {
		rc = read(fd, buf + offset, size - offset);
		if (rc == -1) {
			perror ("insmod: read");
			goto err;
		}
		offset += rc;
	} while (offset < size);

	if (init_module(buf, size, "") != 0) {
		fprintf (stderr, "insmod: init_module: %s: %s\n", module, moderror(errno));
		goto err;
	}

	ret = 0;
out:
	close(fd);
	free(buf);

	return ret;
err:
	ret = -1;
	goto out;
}
#else
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
			perror("fail to open channel device");

		break;
	}

	free(list);
	return fd;
}

int hyper_insmod(char *module)
{
	return 0;
}
#endif

int hyper_open_serial_dev(char *tty)
{
	int fd = open(tty, O_RDWR | O_CLOEXEC | O_NOCTTY);

	if (fd < 0)
		perror("fail to open tty device");

	return fd;
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

	return flags;
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

	return flags;
}

static void hyper_unmount_all(void)
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
		free(filesys);
		mntlist[i] = NULL;
	}

	sync();
}

void hyper_shutdown()
{
	hyper_send_msg_block(ctl.chan.fd, ACK, 0, NULL);
	hyper_unmount_all();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
}
