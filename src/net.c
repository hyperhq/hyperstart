#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <termios.h>
#include <sched.h>

#include "hyper.h"
#include "util.h"
#include "parse.h"
#include "netlink.h"
#include "../config.h"

void hyper_set_be32(uint8_t *buf, uint32_t val)
{
	buf[0] = val >> 24;
	buf[1] = val >> 16;
	buf[2] = val >> 8;
	buf[3] = val;
}

uint32_t hyper_get_be32(uint8_t *buf)
{
	return buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
}

void hyper_set_be64(uint8_t *buf, uint64_t val)
{
	hyper_set_be32(buf, val >> 32);
	hyper_set_be32(buf + 4, val);
}

uint64_t hyper_get_be64(uint8_t *buf)
{
	uint64_t v;

	v = (uint64_t) hyper_get_be32(buf) << 32;
	v |= hyper_get_be32(buf + 4);
	return v;
}

int hyper_send_data(int fd, uint8_t *data, uint32_t len)
{
	int length = 0, size;

	while (length < len) {
		size = write(fd, data + length, len - length);
		if (size <= 0) {
			if (errno == EINTR)
				continue;
			/* EAGAIN means unblock and the peer of virtio-ports is disappear */
			if (errno == EAGAIN)
				return 0;

			perror("send hyper data failed");
			return -1;
		}
		length += size;
	}

	return 0;
}

int hyper_send_data_block(int fd, uint8_t *data, uint32_t len)
{
	int ret, flags;

	flags = hyper_setfd_block(fd);
	if (flags < 0) {
		fprintf(stderr, "%s fail to set fd block\n", __func__);
		return -1;
	}

	ret = hyper_send_data(fd, data, len);

	if (fcntl(fd, F_SETFL, flags) < 0) {
		perror("restore fd flag failed");
		return -1;
	}

	return ret;
}

static int get_addr_ipv4(uint8_t *ap, const char *cp)
{
	int i;

	for (i = 0; i < 4; i++) {
		unsigned long n;
		char *endp;

		n = strtoul(cp, &endp, 0);
		if (n > 255)
			return -1;      /* bogus network value */

		if (endp == cp) /* no digits */
			return -1;
		ap[i] = n;

		if (*endp == '\0')
			break;

		if (i == 3 || *endp != '.')
			return -1;      /* extra characters */

		cp = endp + 1;
	}

	return 1;
}

static int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
		return -1;
	rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
	return 0;
}

static int hyper_get_ifindex(char *nic, struct hyper_pod *pod)
{
	int fd, ifindex = -1;
	char path[512], buf[8];

	sprintf(path, "/sys/class/net/%s/ifindex", nic);
	fprintf(stdout, "net device sys path is %s\n", path);

	if (access(path, R_OK) < 0) {
		sprintf(path, "/net/%s/", nic);
		if (hyper_netlink_wait_dev(pod->ueventfd, path) < 0)
			return -1;
		sprintf(path, "/sys/class/net/%s/ifindex", nic);
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("can not open file");
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	if (read(fd, buf, sizeof(buf) - 1) <= 0) {
		perror("can read open file");
		goto out;
	}

	ifindex = atoi(buf);
	fprintf(stdout, "get ifindex %d\n", ifindex);
out:
	close(fd);
	return ifindex;
}

static int netlink_open(struct rtnl_handle *rth)
{
	memset(rth, 0, sizeof(*rth));

	rth->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rth->fd < 0) {
		perror("cannot open netlink socket");
		return -1;
	}

	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = 0;

	if (bind(rth->fd, (struct sockaddr *)&rth->local, sizeof(rth->local)) < 0) {
		perror("cannot bind netlink socket");
		goto out;
	}

	rth->seq = 0;
	return 0;
out:
	close(rth->fd);
	return -1;
}

static void netlink_close(struct rtnl_handle *rth)
{
	if (rth->fd > 0)
		close(rth->fd);
	rth->fd = -1;
}

static int rtnl_talk(struct rtnl_handle *rtnl,
		     struct nlmsghdr *n, pid_t peer,
		     unsigned groups, struct nlmsghdr *answer)
{
	int status;
	struct sockaddr_nl nladdr;
	struct iovec iov = { (void *)n, n->nlmsg_len };
	struct msghdr msg = { (void *)&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;
	n->nlmsg_seq = ++rtnl->seq;
	if (answer == NULL)
		n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(rtnl->fd, &msg, 0);
	if (status < 0)
		return -1;

	return 0;
}

static int hyper_up_nic(struct rtnl_handle *rth, int ifindex)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[1024];
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_change |= IFF_UP;
	req.i.ifi_flags |= IFF_UP;
	req.i.ifi_index = ifindex;

	if (rtnl_talk(rth, &req.n, 0, 0, NULL) < 0)
		return -1;

	return 0;
}

static int mask2bits(uint32_t netmask)
{
	unsigned bits = 0;
	uint32_t mask = ntohl(netmask);
	uint32_t host = ~mask;

	/* a valid netmask must be 2^n - 1 */
	if ((host & (host + 1)) != 0)
		return -1;

	for (; mask; mask <<= 1)
		++bits;

	return bits;
}

static int get_netmask(unsigned *val, const char *addr)
{
	char *ptr;
	unsigned long res;
	uint32_t data;
	int b;

	res = strtoul(addr, &ptr, 0);

	if (!ptr || ptr == addr || *ptr)
		goto get_addr;

	if (res == ULONG_MAX && errno == ERANGE)
		goto get_addr;

	if (res > UINT_MAX)
		goto get_addr;

	*val = res;
	return 0;

get_addr:
	if (get_addr_ipv4((uint8_t *)&data, addr) <= 0)
		return -1;

	b = mask2bits(data);
	if (b < 0)
		return -1;

	*val = b;
	return 0;
}

static int hyper_setup_route(struct rtnl_handle *rth,
			     struct hyper_route *rt,
			     struct hyper_pod *pod)
{
	uint32_t data;
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;

	if (!rt->dst) {
		fprintf(stderr, "route dest is null\n");
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_NEWROUTE;

	req.r.rtm_family = AF_INET;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_scope = RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;
	req.r.rtm_protocol = RTPROT_BOOT;
	req.r.rtm_dst_len = 0;

	if (rt->gw) {
		if (get_addr_ipv4((uint8_t *)&data, rt->gw) <= 0) {
			fprintf(stderr, "get gw failed\n");
			return -1;
		}

		if (addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &data, 4)) {
			fprintf(stderr, "setup gateway attr failed\n");
			return -1;
		}
	}

	if (rt->device) {
		int ifindex = hyper_get_ifindex(rt->device, pod);
		if (ifindex < 0) {
			fprintf(stderr, "failed to get the ifindix of %s\n", rt->device);
			return -1;
		}

		if (addattr_l(&req.n, sizeof(req), RTA_OIF, &ifindex, 4)) {
			fprintf(stderr, "setup oif attr failed\n");
			return -1;
		}
	}

	if (strcmp(rt->dst, "default") && strcmp(rt->dst, "any") && strcmp(rt->dst, "all")) {
		unsigned mask;
		char *slash = strchr(rt->dst, '/');

		req.r.rtm_dst_len = 32;

		if (slash)
			*slash = 0;

		if (get_addr_ipv4((uint8_t *)&data, rt->dst) <= 0) {
			fprintf(stderr, "get dst failed\n");
			return -1;
		}

		if (addattr_l(&req.n, sizeof(req), RTA_DST, &data, 4)) {
			fprintf(stderr, "setup gateway attr failed\n");
			return -1;
		}

		if (slash) {
			if (get_netmask(&mask, slash + 1) < 0) {
				fprintf(stderr, "get netmask failed\n");
				return -1;
			}
			req.r.rtm_dst_len = mask;
			*slash = '/';
		}
	}

	if (rtnl_talk(rth, &req.n, 0, 0, NULL) < 0) {
		fprintf(stderr, "rtnl talk failed\n");
		return -1;
	}

	return 0;
}

static int hyper_set_interface_attr(struct rtnl_handle *rth,
				int ifindex,
				void *data,
				int len,
				int type)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[1024];
	} req;

	if (!rth || ifindex < 0)
		return -1;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_SETLINK;

	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_change = 0xFFFFFFFF;
	req.i.ifi_index = ifindex;

	if (addattr_l(&req.n, sizeof(req), type,
			data,
			len)) {
                fprintf(stderr, "setup attr failed\n");
                return -1;
        }

	if (rtnl_talk(rth, &req.n, 0, 0, NULL) < 0){
		perror("rtnl_talk failed");
		return -1;
	}

	return 0;
}

static int hyper_set_interface_ipaddrs(struct rtnl_handle *rth,
				int ifindex,
				struct list_head* ipaddresses){
	uint8_t data[4];
	unsigned mask;
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[256];
	} req;
	struct hyper_ipaddress *ip;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	req.ifa.ifa_family = AF_INET;
	req.ifa.ifa_index = ifindex;
	req.ifa.ifa_scope = 0;

	list_for_each_entry(ip, ipaddresses, list) {
		if (ip->addr[0]=='\0'){
			continue;
		} else if (ip->addr[0]=='-') {
			//start with '-' means delete an existing address
			req.n.nlmsg_flags = NLM_F_REQUEST;
			req.n.nlmsg_type = RTM_DELADDR;;
			if (get_addr_ipv4((uint8_t *)&data, &ip->addr[1]) <= 0) {
				fprintf(stderr, "get addr failed\n");
				return -1;
			}
		} else{
			req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
			req.n.nlmsg_type = RTM_NEWADDR;
			if (get_addr_ipv4((uint8_t *)&data, ip->addr) <= 0) {
				fprintf(stderr, "get addr failed\n");
				return -1;
			}
		}

		if (addattr_l(&req.n, sizeof(req), IFA_LOCAL, &data, 4)) {
			fprintf(stderr, "setup attr failed\n");
			return -1;
		}

		if (get_netmask(&mask, ip->mask) < 0) {
			fprintf(stderr, "get netamsk failed\n");
			return -1;
		}

		req.ifa.ifa_prefixlen = mask;
		fprintf(stdout, "interface get netamsk %d %s\n", req.ifa.ifa_prefixlen, ip->mask);
		if (rtnl_talk(rth, &req.n, 0, 0, NULL) < 0) {
			perror("rtnl_talk failed");
			return -1;
		}
	}
	return 0;
}

static int hyper_set_interface_name(struct rtnl_handle *rth,
				int ifindex,
				char *new_device_name)
{
	if ( !rth || ifindex < 0 || !new_device_name) {
		return -1;
	}
	return hyper_set_interface_attr(rth, ifindex, 
				new_device_name,
				strlen(new_device_name)+1,
				IFLA_IFNAME);
}

static int hyper_set_interface_mtu(struct rtnl_handle *rth,
				int ifindex,
				unsigned int mtu)
{
	if (!rth || ifindex < 0) {
		return -1;
	}
	return hyper_set_interface_attr(rth, ifindex, &mtu,
				sizeof(mtu),
				IFLA_MTU);
}

static int hyper_setup_interface(struct rtnl_handle *rth,
			         struct hyper_interface *iface,
				 struct hyper_pod *pod)
{
	int ifindex;
	if (!iface->device) {
		fprintf(stderr, "device name can't be empty\n");
		return -1;
	}

	ifindex = hyper_get_ifindex(iface->device, pod);
	if (ifindex < 0) {
		fprintf(stderr, "failed to get the ifindix of %s\n", iface->device);
		return -1;
	}

	if (!list_empty(&iface->ipaddresses)) {
		if (hyper_set_interface_ipaddrs(rth, ifindex, &iface->ipaddresses) < 0) {
			fprintf(stderr, "set ip addresses failed for interface %s\n", 
					iface->device);
			return -1;
		}
	}

	if (iface->new_device_name && strcmp(iface->new_device_name, iface->device)) {
		fprintf(stdout, "Setting interface name to %s\n", iface->new_device_name);
		hyper_set_interface_name(rth, ifindex, iface->new_device_name);
	}

	if (iface->mtu > 0) {
		fprintf(stdout, "Setting interface MTU to %d\n", iface->mtu);
		if (hyper_set_interface_mtu(rth, ifindex, iface->mtu) < 0) {
			fprintf(stderr, "set mtu failed for interface %s\n", 
					iface->device);
			return -1;
		}
	}

	if (hyper_up_nic(rth, ifindex) < 0) {
		fprintf(stderr, "up device %d failed\n", ifindex);
		return -1;
	}

	return 0;
}

int hyper_rescan(void)
{
	int fd = open("/sys/bus/pci/rescan", O_WRONLY);

	if (fd < 0) {
		perror("can not open rescan file");
		return -1;
	}

	if (write(fd, "1\n", 2) < 0) {
		perror("can not open rescan file");
		close(fd);
		return -1;
	}
	fprintf(stdout, "finish rescan\n");
	close(fd);
	return 0;
}

int hyper_setup_network(struct hyper_pod *pod)
{
	int i, ret = 0;
	struct hyper_interface *iface;
	struct hyper_route *rt;
	struct rtnl_handle rth;

	if (hyper_rescan() < 0)
		return -1;

	if (netlink_open(&rth) < 0)
		return -1;

	for (i = 0; i < pod->i_num; i++) {
		iface = &pod->iface[i];

		ret = hyper_setup_interface(&rth, iface, pod);
		if (ret < 0) {
			fprintf(stderr, "link up device %s failed\n", iface->device);
			goto out;
		}
	}

	ret = hyper_up_nic(&rth, 1);
	if (ret < 0) {
		fprintf(stderr, "link up lo device failed\n");
		goto out;
	}

	for (i = 0; i < pod->r_num; i++) {
		rt = &pod->rt[i];

		ret = hyper_setup_route(&rth, rt, pod);
		if (ret < 0) {
			fprintf(stderr, "setup route failed\n");
			goto out;
		}
	}

out:
	netlink_close(&rth);
	return ret;
}

int hyper_cmd_setup_interface(char *json, int length, struct hyper_pod *pod)
{
	int ret = -1;
	struct hyper_interface *iface;
	struct rtnl_handle rth;

	if (hyper_rescan() < 0)
		return -1;

	if (netlink_open(&rth) < 0)
		return -1;

	iface = hyper_parse_setup_interface(json, length);
	if (iface == NULL) {
		fprintf(stderr, "parse interface failed\n");
		goto out;
	}
	ret = hyper_setup_interface(&rth, iface, pod);
	if (ret < 0) {
		fprintf(stderr, "link up device %s failed\n", iface->device);
		goto out1;
	}
	ret = 0;
out1:
	hyper_free_interface(iface);
	free(iface);
out:
	netlink_close(&rth);
	return ret;
}

static int hyper_remove_nic(char *device)
{
	char path[256], real[128];
	int fd;
	ssize_t size;

	sprintf(path, "/sys/class/net/%s", device);

	size = readlink(path, real, 128);
	if (size < 0 || size > 127) {
		perror("fail to read link directory");
		return -1;
	}

	real[size] = '\0';
	sprintf(path, "/sys/%s/../../../remove", real + 5);

	fprintf(stdout, "get net sys path %s\n", path);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		perror("open file failed");
		return -1;
	}

	if (write(fd, "1\n", 2) < 0) {
		perror("write 1 to file failed");
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}

int hyper_cmd_delete_interface(char *json, int length)
{
	int ret = -1;
	struct hyper_interface *iface;
	struct rtnl_handle rth;

	fprintf(stdout, "client demands to remove network interface\n");
	if (netlink_open(&rth) < 0)
		return -1;

	iface = hyper_parse_setup_interface(json, length);
	if (iface == NULL) {
		fprintf(stderr, "parse interface failed\n");
		goto out;
	}

	if (hyper_remove_nic(iface->device) < 0){
		fprintf(stderr, "remove device %s failed\n", iface->device);
		goto out1;
	}
	fprintf(stdout, "remove device %s successfully\n", iface->device);
	ret = 0;
out1:
	hyper_free_interface(iface);
	free(iface);
out:
	netlink_close(&rth);
	return ret;
}

int hyper_cmd_setup_route(char *json, int length, struct hyper_pod *pod)
{
	struct hyper_route *rts = NULL;
	int i, ret = -1;
	uint32_t r_num;
	struct rtnl_handle rth;

	if (netlink_open(&rth) < 0)
		return -1;

	if (hyper_parse_setup_routes(&rts, &r_num, json, length) < 0) {
		fprintf(stderr, "parse route failed\n");
		goto out;
	}

	for (i = 0; i < r_num; i++) {
		ret = hyper_setup_route(&rth, &rts[i], pod);
		if (ret < 0) {
			fprintf(stderr, "setup route failed\n");
			goto out;
		}
	}

	ret = 0;
out:
	netlink_close(&rth);
	free(rts);
	return ret;
}

int hyper_setup_hostname(struct hyper_pod *pod)
{
	int l, fd, ret = -1, len = 0, size = 0;
	char buf[512];

	if (pod->hostname == NULL)
		return 0;

	fd = open("/tmp/hyper/hostname", O_CREAT| O_TRUNC| O_WRONLY, 0644);
	if (fd < 0) {
		perror("create /tmp/hostname failed");
		return -1;
	}

	size = snprintf(buf, sizeof(buf), "%s\n", pod->hostname);
	if (size < 0) {
		fprintf(stderr, "sprintf hostname failed\n");
		goto out;
	}

	while (len < size) {
		l = write(fd, buf + len, size - len);
		if (l < 0) {
			perror("fail to write hostname");
			goto out;
		}
		len += l;
	}
	ret = 0;
out:
	close(fd);
	return ret;
}

int hyper_write_dns_file(int fd, char *field, char **data, int num)
{
	int i = 0, len = 0, ret = -1, size;
	char *newbuf, *buf = NULL;

	if (num == 0)
		return 0;

	size = strlen(field);
	// 1 for last '\n'
	buf = malloc(size + 1);
	if (buf == NULL) {
		fprintf(stderr, "fail to malloc buff for %s\n", field);
		goto out;
	}
	memcpy(buf, field, size);
	for (i = 0; i < num; i++) {
		// 1 for space
		int new_size = size + strlen(data[i]) + 1;
		newbuf = realloc(buf, new_size + 1);
		if (newbuf == NULL) {
			fprintf(stderr, "fail to realloc buff for %s\n", field);
			goto out;
		}
		buf = newbuf;
		buf[size]= ' ';
		memcpy(buf + size + 1, data[i], strlen(data[i]));
		fprintf(stdout, "%s: data: %s\n", field, buf);
		size = new_size;
	}

	buf[size] = '\n';
	size += 1;
	while (len < size) {
		i = write(fd, buf + len, size - len);
		if (i < 0) {
			perror("fail to write resolv.conf");
			goto out;
		}
		len += i;
	}

	ret = 0;
out:
	free(buf);
	return ret;
}

int hyper_setup_dns(struct hyper_pod *pod)
{
	int i, fd, ret = -1;
	char buf[28];
	int len = 0, size = 0;

	if (pod->dns == NULL)
		return 0;

	fd = open("/tmp/hyper/resolv.conf", O_CREAT| O_TRUNC| O_WRONLY, 0644);

	if (fd < 0) {
		perror("create /tmp/resolv.conf failed");
		return -1;
	}

	for (i = 0; i < pod->d_num; i++) {
		int l;
		len = 0;
		size = snprintf(buf, sizeof(buf), "nameserver %s\n", pod->dns[i]);
		if (size < 0) {
			fprintf(stderr, "sprintf resolv.conf entry failed\n");
			goto out;
		}

		while (len < size) {
			l = write(fd, buf + len, size - len);
			if (l < 0) {
				perror("fail to write resolv.conf");
				goto out;
			}
			len += l;
		}
	}

	if (hyper_write_dns_file(fd, "search", pod->dns_search, pod->dsearch_num) < 0 ||
	    hyper_write_dns_file(fd, "options", pod->dns_option, pod->doption_num) < 0) {
		goto out;
	}

	ret = 0;
out:
	close(fd);
	return ret;
}

