#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "hyper.h"
#include "util.h"
#include "../config.h"

int hyper_init_modules() 
{
	int status = hyper_cmd("depmod");
	if (status != 0) {
		fprintf(stderr, "depmod failed, status: %d\n", status);
		return -1;
	}

	return 0;
}

int hyper_setup_iptables_rule(struct ipt_rule rule)
{
	char check_cmd[512] = {0};
	char cmd[512] = {0};
	int check = -1;

	if (rule.rule != NULL) {
		sprintf(check_cmd, "iptables -t %s -C %s %s", rule.table, rule.chain, rule.rule);
		sprintf(cmd, "iptables -t %s %s %s %s", rule.table, rule.op, rule.chain, rule.rule);
	} else {
		sprintf(cmd, "iptables -t %s %s %s", rule.table, rule.op, rule.chain);
	}

	if (strlen(check_cmd) > 0) {
		check = hyper_cmd(check_cmd);
		fprintf(stdout, "check iptables '%s', ret: %d\n", check_cmd, check);
	}

	if (check == 0) {
		// iptables rule already exist, do not insert it again
		if (!strncmp(rule.op, "-A", strlen("-A")) ||
			!strncmp(rule.op, "-I", strlen("-I")) ||
			!strncmp(rule.op, "-N", strlen("-N"))) {
			fprintf(stdout, "iptables rule '%s' already exist\n", rule.rule);
			return 0;
		}
	}

	int status = hyper_cmd(cmd);
	fprintf(stdout, "insert iptables '%s', ret: %d\n", cmd, status);
	if (status != 0) {
		fprintf(stderr, "insert iptables rule failed, ret: %d\n", status);
		return -1;
	}

	return 0;
}

// initialize modules and iptables chains
int hyper_setup_portmapping(struct hyper_pod *pod)
{
	const char *connmax = "10485760";
	const char *timeout = "300";

	if (pod->portmap_white_lists == NULL || (pod->portmap_white_lists->i_num == 0 &&
			pod->portmap_white_lists->e_num == 0)) {
		return 0;
	}

	if (hyper_init_modules() < 0) {
		return -1;
	}

	// iptables -t filter -N hyperstart-INPUT
	// iptables -t nat -N hyperstart-PREROUTING
	// iptables -t filter -I INPUT -j hyperstart-INPUT
	// iptables -t nat -I PREROUTING -j hyperstart-PREROUTING
	// iptables -t filter -A hyperstart-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	// iptables -t filter -A hyperstart-INPUT -p icmp -j ACCEPT
	// iptables -t filter -A hyperstart-INPUT -i lo -j ACCEPT
	// iptables -t filter -A hyperstart-INPUT -j DROP
	// iptables -t nat -A hyperstart-PREROUTING -j RETURN
	const struct ipt_rule rules[] = {
		{
			.table = "filter",
			.op = "-N",
			.chain = "hyperstart-INPUT",
			.rule = NULL,
		},
		{
			.table = "nat",
			.op = "-N",
			.chain = "hyperstart-PREROUTING",
			.rule = NULL,
		},
		{
			.table = "filter",
			.op = "-I",
			.chain = "INPUT",
			.rule = "-j hyperstart-INPUT",
		},
		{
			.table = "nat",
			.op = "-I",
			.chain = "PREROUTING",
			.rule = "-j hyperstart-PREROUTING",
		},
		{
			.table = "filter",
			.op = "-A",
			.chain = "hyperstart-INPUT",
			.rule = "-m state --state RELATED,ESTABLISHED -j ACCEPT",
		},
		{
			.table = "filter",
			.op = "-A",
			.chain = "hyperstart-INPUT",
			.rule = "-p icmp -j ACCEPT",
		},
		{
			.table = "filter",
			.op = "-A",
			.chain = "hyperstart-INPUT",
			.rule = "-i lo -j ACCEPT",
		},
		{
			.table = "filter",
			.op = "-A",
			.chain = "hyperstart-INPUT",
			.rule = "-j DROP",
		},
		{
			.table = "nat",
			.op = "-A",
			.chain = "hyperstart-PREROUTING",
			.rule = "-j RETURN",
		},
	};

	int i = 0;
	for(i=0; i< sizeof(rules)/sizeof(struct ipt_rule); i++) {
		if (hyper_setup_iptables_rule(rules[i])<0) {
			return -1;
		}
	}

	/* portmapping enables nf_conntrack by default, should blow up nf_conntack_max to make sure
	 * nf_conntrack is available for connections. */
	if (hyper_write_file("/proc/sys/net/nf_conntrack_max", connmax, strlen(connmax)) < 0) {
		fprintf(stderr, "sysctl: setup default nf_conntrack_max(%s) failed\n", connmax);
	}

	if (hyper_write_file("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established", timeout, strlen(timeout)) < 0) {
		fprintf(stderr, "sysctl: setup default nf_conntrack_tcp_timeout_established(%s) failed\n", timeout);
	}

	return 0;
}

int hyper_setup_container_portmapping(struct hyper_container *c, struct hyper_pod *pod)
{
	// only allow network request from internal white list
	int i = 0, j = 0;
	char rule[128] = {0};
	char iptables_restore[512];

	// restore iptables rules
	if (sprintf(iptables_restore, "iptables-restore /tmp/hyper/shared/%s-iptables", c->id) > 0) {
		hyper_cmd(iptables_restore);
	}

	if (pod->portmap_white_lists == NULL || (pod->portmap_white_lists->i_num == 0 &&
			pod->portmap_white_lists->e_num == 0)) {
		return 0;
	}

	for (j=0; j<pod->portmap_white_lists->i_num; j++) {
		sprintf(rule, "-s %s -j ACCEPT",
			pod->portmap_white_lists->internal_networks[j]);
		struct ipt_rule accept_rule = {
			.table = "filter",
			.op = "-I",
			.chain = "hyperstart-INPUT",
			.rule = rule,
		};
		if (hyper_setup_iptables_rule(accept_rule)<0) {
			fprintf(stderr, "setup accept_rule '%s' failed\n", rule);
			return -1;
		}
	}

	if (c->ports_num == 0) {
		return 0;
	}

	char *network = NULL;
	for (i=0; i<c->ports_num; i++) {
		// setup port mapping only if host_port is set
		if (c->ports[i].host_port > 0) {
			for (j=0; j<pod->portmap_white_lists->e_num; j++) {
				network = pod->portmap_white_lists->external_networks[j];

				// redirect host_port to container_port
				if (c->ports[i].host_port != c->ports[i].container_port) {
					sprintf(rule, "-s %s -p %s -m %s --dport %d -j REDIRECT --to-ports %d",
						network,
						c->ports[i].protocol,
						c->ports[i].protocol,
						c->ports[i].host_port,
						c->ports[i].container_port);
					struct ipt_rule redirect_rule = {
						.table = "nat",
						.op = "-I",
						.chain = "hyperstart-PREROUTING",
						.rule = rule,
					};
					if (hyper_setup_iptables_rule(redirect_rule)<0) {
						fprintf(stderr, "setup redirect_rule '%s' failed\n", rule);
						return -1;
					}
				}

				// open container_port to external network
				sprintf(rule, "-s %s -p %s -m %s --dport %d -j ACCEPT",
					network,
					c->ports[i].protocol,
					c->ports[i].protocol,
					c->ports[i].container_port);
				struct ipt_rule accept_rule = {
					.table = "filter",
					.op = "-I",
					.chain = "hyperstart-INPUT",
					.rule = rule,
				};
				if (hyper_setup_iptables_rule(accept_rule)<0) {
					fprintf(stderr, "setup accept_rule '%s' failed\n", rule);
					return -1;
				}
			}
		}
	}

	return 0;
}

void hyper_cleanup_container_portmapping(struct hyper_container *c, struct hyper_pod *pod)
{
	if (pod->portmap_white_lists == NULL || (pod->portmap_white_lists->i_num == 0 &&
			pod->portmap_white_lists->e_num == 0)) {
		return;
	}

	int i = 0, j = 0;
	char rule[128] = {0};
	for (j=0; j<pod->portmap_white_lists->i_num; j++) {
		sprintf(rule, "-s %s -j ACCEPT",
			pod->portmap_white_lists->internal_networks[j]);
		struct ipt_rule accept_rule = {
			.table = "filter",
			.op = "-D",
			.chain = "hyperstart-INPUT",
			.rule = rule,
		};
		if (hyper_setup_iptables_rule(accept_rule)<0) {
			fprintf(stderr, "cleanup accept_rule '%s' failed\n", rule);
		}
	}

	if (c->ports_num == 0) {
		return;
	}

	char *network = NULL;
	for (i=0; i<c->ports_num; i++) {
		// clean up port mapping only if host_port is set
		if (c->ports[i].host_port > 0) {
			for (j=0; j<pod->portmap_white_lists->e_num; j++) {
				network = pod->portmap_white_lists->external_networks[j];

				//  delete rules redirecting host_port to container_port
				if (c->ports[i].host_port != c->ports[i].container_port) {
					sprintf(rule, "-s %s -p %s -m %s --dport %d -j REDIRECT --to-ports %d",
						network,
						c->ports[i].protocol,
						c->ports[i].protocol,
						c->ports[i].host_port,
						c->ports[i].container_port);
					struct ipt_rule redirect_rule = {
						.table = "nat",
						.op = "-D",
						.chain = "hyperstart-PREROUTING",
						.rule = rule,
					};
					if (hyper_setup_iptables_rule(redirect_rule)<0) {
						fprintf(stderr, "cleanup redirect '%s' failed\n", rule);
					}
				}

				// open container_port to external network
				sprintf(rule, "-s %s -p %s -m %s --dport %d -j ACCEPT",
					network,
					c->ports[i].protocol,
					c->ports[i].protocol,
					c->ports[i].container_port);
				struct ipt_rule accept_rule = {
					.table = "filter",
					.op = "-D",
					.chain = "hyperstart-INPUT",
					.rule = rule,
				};
				if (hyper_setup_iptables_rule(accept_rule)<0) {
					fprintf(stderr, "cleanup accept_rule '%s' failed\n", rule);
				}
			}
		}
	}
}
