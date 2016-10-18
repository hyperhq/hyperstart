#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/pci_regs.h>
#include <linux/virtio_ids.h>
#include <linux/vm_sockets.h>

#include "event.h"

/* for pre-vsock kernels. */
#ifndef VIRTIO_ID_VSOCK
 #define VIRTIO_ID_VSOCK 0x13
#endif
#ifndef AF_VSOCK
 #define AF_VSOCK 40
#endif

/* include/linux/pci_ids.h. It can be read from file pci.ids but why the dependency? */
#ifndef PCI_SUBVENDOR_ID_REDHAT_QUMRANET
 #define PCI_SUBVENDOR_ID_REDHAT_QUMRANET 0x1af4
#endif
static int check_vsock_config(const char *conf)
{
	unsigned char config[64];
	unsigned int vendor, id;
	int fd, size;

	fd = open(conf, O_RDONLY);
	if (fd < 0) {
		perror("failed to open pci dev config");
		return -1;
	}
	size = read(fd, config, 64);
	close(fd);
	if (size != 64) {
		fprintf(stderr, "short read of %s\n", conf);
		return -1;
	}

	/* vendor and ID are both 2 bytes */
	vendor = config[PCI_SUBSYSTEM_VENDOR_ID] | (config[PCI_SUBSYSTEM_VENDOR_ID+1] << 8);
	id = config[PCI_SUBSYSTEM_ID] | (config[PCI_SUBSYSTEM_ID+1] << 8);
	fprintf(stdout, "found vendor: %x ID: %x\n", vendor, id);

	if (vendor == PCI_SUBVENDOR_ID_REDHAT_QUMRANET && id == VIRTIO_ID_VSOCK) {
		return 1;
	}

	return 0;
}

const char *pci_device_dir = "/sys/bus/pci/devices/";
int probe_vsock_device(void)
{
	struct dirent **list;
	char config_file[512];
	int i, num, found = 0;

	num = scandir(pci_device_dir, &list, NULL, NULL);
	if (num < 0) {
		perror("scan pci device dir failed");
		return -1;
	}

	for (i = 0; i < num; i++) {
		if (found == 0 &&
		    strcmp(list[i]->d_name, ".") != 0 && strcmp(list[i]->d_name, "..") != 0) {
			fprintf(stdout, "probe %s/%s\n", pci_device_dir, list[i]->d_name);
			sprintf(config_file, "%s/%s/config", pci_device_dir, list[i]->d_name);
			if (check_vsock_config(config_file) > 0) {
				found = 1;
			}
		}
		free(list[i]);
	}

	free(list);
	return found;
}

int hyper_create_vsock_listener(unsigned short port)
{
	int fd;
	struct sockaddr_vm sa_listen = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_ANY,
		.svm_port = port,
	};

	fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("fail to create vsock socket");
		return -1;
	}

	if (bind(fd, (struct sockaddr*)&sa_listen, sizeof(sa_listen)) < 0) {
		perror("fail to bind vsock");
		close(fd);
		return -1;
	}

	if (listen(fd, SOMAXCONN) < 0) {
		perror("fail to listen vsock");
		close(fd);
		return -1;
	}

	return fd;
}

int hyper_vsock_accept(struct hyper_event *he, int efd, int events)
{
	int ret = 0;

	while(1) {
		struct sockaddr_vm sa_client;
		socklen_t sa_len = sizeof(sa_client);
		int fd;

		fd = accept(he->fd, (struct sockaddr*)&sa_client, &sa_len);
		if (fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* We have processed all incoming connections. */
				break;
			} else {
				perror ("fail to accept vsock connection");
				ret = -1;
				break;
			}
		}
		fprintf(stdout, "vsock connection from cid %u port %u\n",
			sa_client.svm_cid, sa_client.svm_port);
		close(fd);
	}

	return ret;
}
