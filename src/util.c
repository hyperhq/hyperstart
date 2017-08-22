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
#include <grp.h>
#include <pwd.h>
#include <libgen.h>
#include <termios.h>

#include "util.h"
#include "hyper.h"
#include "container.h"
#include "../config.h"

int hyper_setup_env(struct env *envs, int num, bool setPATH)
{
	int i, ret = 0;
	struct env *env;
	if (setPATH) {
		ret = setenv("PATH", "/usr/local/bin:/usr/bin:/bin:.", 1);
		if (ret < 0) {
			perror("fail to setup default PATH");
			ret = -1;
		}
	}

	for (i = 0; i < num; i++) {
		env = &envs[i];
		if (setenv(env->env, env->value, 1) < 0) {
			perror("fail to setup env");
			ret = -1;
			continue;
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

int hyper_copy_dir(char *src, char *dest)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "tar cf - -C %s . | tar fx - -C %s", src, dest);

	return hyper_cmd(cmd);
}

void hyper_sync_time_hctosys() {
	int pid;
	pid = fork();
	if (pid < 0) {
		perror("fail to fork to copy directory");
	} else if (pid == 0) {
		execlp("hwclock", "hwclock", "-s", NULL);
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

static unsigned long id_or_max(const char *name)
{
	char *ptr;
	errno = 0;
	long id = strtol(name, &ptr, 10);
	if (name == ptr || id < 0 || (errno != 0 && id == 0) || *ptr != '\0')
		return ~0UL;
	return id;
}

// Checks if the name provided is a numeric value and does the conversion.
bool hyper_name_to_id(const char *name, unsigned long *val)
{
	char *ptr;
	errno = 0;
	long id = strtol(name, &ptr, 10);
	if (name == ptr || id < 0 || (errno != 0 && id == 0) || *ptr != '\0')
		return false;
	*val = id;
	return true;
}

// the same as getpwnam(), but it only parses /etc/passwd and allows name to be id string
struct passwd *hyper_getpwnam(const char *name)
{
	uid_t uid = (uid_t)id_or_max(name);
	FILE *file = fopen("/etc/passwd", "r");
	if (!file) {
		perror("faile to open /etc/passwd");
		return NULL;
	}
	for (;;) {
		struct passwd *pwd = fgetpwent(file);
		if (!pwd)
			break;
		if (!strcmp(pwd->pw_name, name) || pwd->pw_uid == uid) {
			fclose(file);
			return pwd;
		}
	}
	fclose(file);
	return NULL;
}

// the same as getgrnam(), but it only parses /etc/group and allows the name to be id string
struct group *hyper_getgrnam(const char *name)
{
	gid_t gid = (gid_t)id_or_max(name);
	FILE *file = fopen("/etc/group", "r");
	if (!file) {
		perror("faile to open /etc/group");
		return NULL;
	}
	for (;;) {
		struct group *gr = fgetgrent(file);
		if (!gr)
			break;
		if (!strcmp(gr->gr_name, name) || gr->gr_gid == gid) {
			fclose(file);
			return gr;
		}
	}
	fclose(file);
	return NULL;
}

// the same as getgrouplist(), but it only parses /etc/group
int hyper_getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups)
{
	int nr = 0, ret;
	FILE *file = fopen("/etc/group", "r");
	if (!file) {
		perror("faile to open /etc/group");
		return -1;
	}
	for (;;) {
		struct group *gr = fgetgrent(file);
		if (!gr)
			break;
		int j;
		for (j = 0; gr->gr_mem && gr->gr_mem[j]; j++) {
			if (!strcmp(gr->gr_mem[j], user)) {
				fprintf(stdout, "hyper_getgrouplist() found matched group for user %s, grname: %s, gid: %d\n", user, gr->gr_name, gr->gr_gid);
				if (nr < *ngroups)
					groups[nr] = gr->gr_gid;
				nr++;
			}
		}
	}
	fclose(file);
	if (nr == 0) {
		fprintf(stdout, "hyper_getgrouplist() adds the default group to list, gid:%d\n", group);
		if (nr < *ngroups)
			groups[nr] = group;
		nr++;
	}
	ret = nr <= *ngroups ? nr : -1;
	*ngroups = nr;
	return ret;
}

int hyper_write_file(const char *path, const char *value, size_t len)
{
	ssize_t size = 0, l;
	int fd = open(path, O_WRONLY);
	if (fd < 0) {
		perror("open file failed");
		return -1;
	}

	while (size < len) {
		l = write(fd, value + size, len - size);
		if (l < 0) {
			perror("fail to write to file");
			close(fd);
			return -1;
		}
		size += l;
	}

	close(fd);
	return 0;
}

/* Trim all trailing '/' of a hyper_path except for the prefix one. */
void hyper_filize(char *hyper_path)
{
	char *p;

	if (strlen(hyper_path) == 0)
		return;

	p = &hyper_path[strlen(hyper_path) - 1];

	for (; *p == '/' && p != hyper_path; p--) {
		*p = '\0';
	}
}

static char *hyper_resolve_link(char *path)
{
	char buf[512];
	int len;

	len = readlink(path, buf, sizeof(buf));
	if (len < 0) {
		perror("failed to read mkdir symlink");
		return NULL;
	} else if (len >= sizeof(buf)) {
		errno = ENAMETOOLONG;
		return NULL;
	}

	buf[len] = '\0';
	fprintf(stdout, "follow link %s\n", buf);
	return strdup(buf);
}

/**
 * hyper_mkdir_follow_link - create directories recurrsively while resolving symlinks
 * 			     as if we were in a chroot jail.
 *
 * @root: chroot jail path.
 * @path: target directory. It is always relative to @root even if it starts with /.
 * @parent: what's already created to the target directory.
 * @link_max: max number of symlinks to follow.
 * @create_file: create last component of @path as a normal file
 *
 * Upon success, @parent is changed to point to resolved path name.
 */
static int hyper_mkdir_follow_link(const char *root, const char *path, char *parent,
				   int *link_max, bool create_file)
{
	char *comp, *next, *prev, *last, *link, *dummy, *npath, *delim = "/";
	struct stat st;
	int fd;

	if (strncmp(root, parent, strlen(root)) != 0) {
		errno = EINVAL;
		return -1;
	}

	npath = strdup(path);
	if (npath == NULL)
		goto out;

	comp = strtok_r(npath, delim, &dummy);
	if (comp == NULL)
		goto out;

	do {
		last = comp;
		next = strtok_r(NULL, delim, &dummy);

		if (!strcmp(comp, "."))
			continue;

		if (!strcmp(comp, "..")) {
			/* *NOTE* this works iff:
			 * 1. parent is initialized as root when entering for the first time.
			 * 2. comp is never appended to parent with trailing '/'.
			 * 3. comp is always appended to parent with *one* prefix '/'.
			 */
			char *p = strrchr(parent, '/');
			if (p == NULL) {
				/* no comp appended, do nothing */
			} else if (p - parent >= strlen(root)) {
				/* go back one level */
				*p = '\0';
			}
			/* no need to check parent directory */
			continue;
		}

		if (strlen(parent) + strlen(comp) + 1 >= 512) {
			errno = ENAMETOOLONG;
			goto out;
		}
		prev = &parent[strlen(parent)];
		strcat(parent, "/");
		strcat(parent, comp);

		if (lstat(parent, &st) >= 0) {
			if ((S_ISDIR(st.st_mode) && (next != NULL || !create_file)) ||
			    (S_ISREG(st.st_mode) && next == NULL && create_file)) {
				continue;
			} else if (S_ISLNK(st.st_mode)) {
				if (--(*link_max) <= 0) {
					errno = ELOOP;
					goto out;
				}
				link = hyper_resolve_link(parent);
				if (link == NULL)
					goto out;
				if (link[0] == '/') {
					sprintf(parent, "%s", root);
				} else {
					*prev = '\0'; /* drop current comp */
				}
				if (hyper_mkdir_follow_link(root, link, parent, link_max, next == NULL && create_file) < 0) {
					free(link);
					goto out;
				}
				free(link);
				continue;
			} else {
				errno = ENOTDIR;
				goto out;
			}
		}

		if (next == NULL && create_file) {
			fprintf(stdout, "create file %s\n", parent);
			fd = open(parent, O_CREAT|O_WRONLY, 0666);
			if (fd < 0)
				goto out;
			close(fd);
		} else {
			fprintf(stdout, "create directory %s\n", parent);
			if (mkdir(parent, 0755) < 0 && errno != EEXIST) {
				perror("failed to create directory");
				goto out;
			}
		}
	} while((comp = next) != NULL);

	if (create_file && (!strcmp(last, ".") || !strcmp(last, "..")))
		errno = ENOTDIR;
	else
		/* reset errno to mark success */
		errno = 0;
out:
	free(npath);
	return errno ? -1 : 0;
}

static int hyper_create_target_at(const char *root, char *hyper_path, int size, bool create_file)
{
	char result[512];
	int max_link = 40;

	sprintf(result, "%s", root);
	if (hyper_mkdir_follow_link(root, hyper_path, result, &max_link, create_file) < 0)
		return -1;

	if (strlen(result) + 1 > size) {
		errno = ENAMETOOLONG;
		return -1;
	}
	sprintf(hyper_path, "%s", result);
	return 0;
}

/*
 * hyper_mkdir_at() is similar to hyper_mkdir() with the exception that
 * when there are symlinks in the path components, it acts as if we created
 * directories in a chroot jail. @hyper_path is always considered relative
 * to root even if it starts with a leading stash ('/').
 *
 * Upon success, @hyper_path is modified to save resolved path in chroot jail.
 */
int hyper_mkdir_at(const char *root, char *hyper_path, int size)
{
	return hyper_create_target_at(root, hyper_path, size, false);
}

/**
 * hyper_create_file_at - create a file in @root chroot jail.
 *
 * @root: chroot jail path.
 * @hyper_path: must point to a file rather than a directory, e.g., having trailing '/'
 * @size: size of @hyper_path storage.
 *
 * Upon success, @hyper_path is modified to point to the path resolved in chroot jail.
 */
int hyper_create_file_at(const char* root, char *hyper_path, int size)
{
	return hyper_create_target_at(root, hyper_path, size, true);
}

int hyper_mkdir(char *path, mode_t mode)
{
	struct stat st;

	if (stat(path, &st) >= 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		errno = ENOTDIR;
		return -1;
	}

	if (errno != ENOENT)
		return -1;

	char *parent_path = strdup(path);
	if (parent_path == NULL) {
		errno = ENOMEM;
		return -1;
	}
	if (hyper_mkdir(dirname(parent_path), mode) < 0) {
		free(parent_path);
		return -1;
	}
	free(parent_path);

	fprintf(stdout, "create directory %s\n", path);
	if (mkdir(path, mode) < 0 && errno != EEXIST) {
		perror("failed to create directory");
		return -1;
	}
	return 0;
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
		sprintf(path, "/sys/devices/system/cpu/cpu%d/online", num);
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
		sprintf(path, "/sys/devices/system/memory/memory%d/online", num);
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

static int hyper_open_serial(char *channel, int mode)
{
	struct termios term;
	int fd = open(channel, O_RDWR | O_CLOEXEC | mode);
	if (fd < 0) {
		perror("fail to open channel device");
		return -1;
	}

	fprintf(stdout, "open %s get %d\n", channel, fd);
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

static int hyper_open_virtio_port(char *channel, int mode)
{
	struct dirent **list;
	struct dirent *dir;
	int fd = -1, i, num;
	char path[256], name[128];

	num = scandir("/sys/class/virtio-ports/", &list, NULL, NULL);
	if (num < 0) {
		perror("scan /sys/class/virtio-ports/ failed");
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
		if (fd < 0)
			continue;
		if (read(fd, name, sizeof(name)) < 0) {
			close(fd);
			continue;
		}

		close(fd);
		fd = -1;

		if (strncmp(name, channel, strlen(channel))) {
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

int hyper_open_channel(char *channel, int mode, bool is_serial)
{
	if (is_serial)
		return hyper_open_serial(channel, mode);

	return hyper_open_virtio_port(channel, mode);
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

void hyper_unmount_all(void)
{
	FILE *mtab;
	struct mntent *mnt;

	mtab = setmntent("/proc/mounts", "r");
	if (mtab == NULL) {
		fprintf(stderr, "cannot open /proc/mount");
		return;
	}

	while (true) {
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

		fprintf(stdout, "umount %s\n", mnt->mnt_dir);
		/*
		 * Umounting root w/o MNT_DETACH will make it readonly.
		 * While it is ok for block devices, we do want to reuse
		 * the same 9p share mount when the container is restarted.
		 *
		 * Just do MNT_DETACH umount because we call sync() afterwards.
		 */
		if (umount2(mnt->mnt_dir, MNT_DETACH) < 0)
			fprintf(stderr, ("umount %s: %s failed\n"),
				mnt->mnt_dir, strerror(errno));
	}

	endmntent(mtab);
	sync();
}

void hyper_shutdown()
{
	hyper_unmount_all();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
}

int hyper_cmd(char *cmd)
{
	int pid, status;

	pid = fork();
	if (pid < 0) {
		perror("fail to fork");
		return -1;
	} else if (pid > 0) {
		if (waitpid(pid, &status, 0) <= 0) {
			perror("waiting fork cmd failed");
			return -1;
		}
		if (WIFEXITED(status)) {
			int ret = WEXITSTATUS(status);
			fprintf(stdout, "%s cmd exit normally, status %" PRIu8 "\n", cmd, ret);
			if (ret == 0)
				return 0;
		}

		fprintf(stdout, "cmd %s exit unexpectedly, status %" PRIu8 "\n", cmd, status);
		return -1;
	} else {
		fprintf(stdout, "executing cmd %s\n", cmd);
		execlp("sh", "sh", "-c", cmd, NULL);
	}

	return -1;
}

ssize_t nonblock_read(int fd, void *buf, size_t count)
{
	ssize_t len = 0, ret = 0;

	errno = 0;
	while (len < count) {
		ret = read(fd, buf + len, count - len);
		if (ret <= 0) {
			if (errno == EINTR) {
				errno = 0;
				continue;
			}
			if (errno == EAGAIN) {
				ret = 0;
			}
			break;
		}

		len += ret;
	}

	return len > 0 ? len : -errno;
}

int hyper_mount_nfs(char *server, char *mountpoint)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "mount.nfs4 -n %s %s", server, mountpoint);

	return hyper_cmd(cmd);
}

int64_t hyper_eventfd_recv(int fd)
{
	int64_t type;
	int size;

	while (1) {
		size = read(fd, &type, sizeof(type));
		if (size != sizeof(type)) {
			if (errno == EINTR)
				continue;

			perror("hyper_eventfd_recv failed");
			return -1;
		}
		break;
	}

	return type;
}

int hyper_eventfd_send(int fd, int64_t type)
{
	int size;

	while (1) {
		size = write(fd, &type, sizeof(type));
		if (size != sizeof(type)) {
			if (errno == EINTR)
				continue;

			perror("hyper_eventfd_send failed");
			return -1;
		}
		break;
	}

	return 0;
}
