#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "../src/hyper.h"
#include "../src/net.h"

int test_sendmsg(int fd, unsigned int type, unsigned int len, char *message)
{
	uint8_t buf[4096];


	/* send hyper info to guest */
	hyper_set_be32(buf, type);

	len += 8;

	fprintf(stdout, "type is %u, len is %u\n", type, len);
	hyper_set_be32(buf + 4, len);

	if (message)
		memcpy(buf + 8, message, len - 8);

	if (write(fd, buf, len) != len) {
		fprintf(stderr, "send SETDVM MESSAGE failed\n");
		return -1;
	}

	fprintf(stdout, "finish sending\n");
	return 0;
}

int test_sendmsg_from_file(int fd, unsigned int type, char *file)
{
	int file_fd = open(file, O_RDONLY);
	uint8_t buf[4096];
	unsigned int len = 0;

	if (file_fd < 0) {
		perror("fail to open file");
		return -1;
	}

	while (len < 4096) {
		int size = read(file_fd, buf + len, sizeof(buf) - len);

		fprintf(stdout, "read %d data\n", size);
		if (size < 0) {
			perror("fail to read data");
			return -1;
		} else if (size == 0) {
			/* buf[len] = '\0';*/
			fprintf(stdout, "get buf %s, call sendmsg\n", buf);
			test_sendmsg(fd, type, len, (char *)buf);
			break;
		}

		len += size;
	}

	close(file_fd);

	if (read(fd, buf, 8) != 8) {
		fprintf(stderr, "read response failed\n");
		return -1;
	}

	type = hyper_get_be32(buf);
	if (type != ACK) {
		fprintf(stderr, "incorrect type %d\n", type);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int sock, fd = -1;
	struct sockaddr_un addr;
	uint8_t buf[8];
	unsigned int type;

	unlink("/tmp/hyper.sock");

	sock = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
	if (sock == -1) {
		perror("create unix socket failed");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "/tmp/hyper.sock", UNIX_PATH_MAX);
	addr.sun_path[UNIX_PATH_MAX - 1] = '\0';

	if (bind(sock, ((struct sockaddr *) &addr), sizeof(addr)) == -1) {
		perror("bind failed");
		goto out;
	}

	if (listen(sock, 1) == -1) {
		perror("bind failed");
		goto out;
	}

	while (fd == -1)
		fd = accept4(sock, NULL, NULL, SOCK_CLOEXEC);

	fprintf(stdout, "connected\n");
	if (read(fd, buf, 8) != 8) {
		fprintf(stderr, "read failed, buf %s\n", buf);
		goto out1;
	}

	type = hyper_get_be32(buf);
	fprintf(stdout, "get type %d\n", type);

	if (type != READY) {
		fprintf(stderr, "incorrect type %d\n", type);
		goto out1;
	}

	fprintf(stdout, "get length %d\n", hyper_get_be32(buf + 4));

	/* test_sendmsg_from_file(fd, SETDVM, "sethyper.json"); */
	if (test_sendmsg_from_file(fd, STARTPOD, "startpod.json") < 0) {
		fprintf(stderr, "send startpod message failed\n");
		goto out1;
	}

	if (test_sendmsg_from_file(fd, EXECCMD, "execcmd.json") < 0) {
		fprintf(stderr, "send execcmd message failed\n");
		goto out1;
	}

	if (test_sendmsg(fd, STOPPOD, 0, NULL) < 0) {
		fprintf(stderr, "send stoppod message failed\n");
		goto out1;
	}

	if (read(fd, buf, 8) != 8) {
		fprintf(stderr, "read response failed\n");
		return -1;
	}

	type = hyper_get_be32(buf);
	if (type != ACK) {
		fprintf(stderr, "incorrect type %d\n", type);
		return -1;
	}

	if (read(fd, buf, 8) != 8) {
		fprintf(stderr, "read response failed\n");
		return -1;
	}
out1:
	close(fd);
out:
	close(sock);

	return 0;
}
