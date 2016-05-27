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
	int status = hyper_cmd("/sbin/depmod");
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
		sprintf(check_cmd, "/sbin/iptables -t %s -C %s %s", rule.table, rule.chain, rule.rule);
		sprintf(cmd, "/sbin/iptables -t %s %s %s %s", rule.table, rule.op, rule.chain, rule.rule);
	} else {
		sprintf(cmd, "/sbin/iptables -t %s %s %s", rule.table, rule.op, rule.chain);
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
	if (pod->w_num == 0) {
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

	return 0;
}

void hyper_cleanup_portmapping(struct hyper_pod *pod)
{
	if (pod->w_num == 0) {
		return;
	}

	// iptables -t filter -D hyperstart-INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	// iptables -t filter -D hyperstart-INPUT -p icmp -j ACCEPT
	// iptables -t filter -D hyperstart-INPUT -i lo -j ACCEPT
	// iptables -t filter -D hyperstart-INPUT -j DROP
	// iptables -t filter -D INPUT -j hyperstart-DNPUT
	// iptables -t nat -D hyperstart-PREROUTING -j RETURN
	// iptables -t nat -D PREROUTING -j hyperstart-PREROUTING
	// iptables -t filter -F hyperstart-INPUT
	// iptables -t nat -F hyperstart-PREROUTING
	// iptables -t filter -X hyperstart-INPUT
	// iptables -t nat -X hyperstart-PREROUTING
	const struct ipt_rule rules[] = {
		{
			.table = "filter",
			.op = "-D",
			.chain = "hyperstart-INPUT",
			.rule = "-m state --state RELATED,ESTABLISHED -j ACCEPT",
		},
		{
			.table = "filter",
			.op = "-D",
			.chain = "hyperstart-INPUT",
			.rule = "-p icmp -j ACCEPT",
		},
		{
			.table = "filter",
			.op = "-D",
			.chain = "hyperstart-INPUT",
			.rule = "-i lo -j ACCEPT",
		},
		{
			.table = "filter",
			.op = "-D",
			.chain = "hyperstart-INPUT",
			.rule = "-j DROP",
		},
		{
			.table = "nat",
			.op = "-D",
			.chain = "hyperstart-PREROUTING",
			.rule = "-j RETURN",
		},
		{
			.table = "nat",
			.op = "-D",
			.chain = "PREROUTING",
			.rule = "-j hyperstart-PREROUTING",
		},
		{
			.table = "filter",
			.op = "-D",
			.chain = "INPUT",
			.rule = "-j hyperstart-INPUT",
		},
		{
			.table = "nat",
			.op = "-F",
			.chain = "hyperstart-PREROUTING",
			.rule = NULL,
		},
		{
			.table = "nat",
			.op = "-X",
			.chain = "hyperstart-PREROUTING",
			.rule = NULL,
		},
		{
			.table = "filter",
			.op = "-F",
			.chain = "hyperstart-INPUT",
			.rule = NULL,
		},
		{
			.table = "filter",
			.op = "-X",
			.chain = "hyperstart-INPUT",
			.rule = NULL,
		},
	};

	int i = 0;
	for(i=0; i< sizeof(rules)/sizeof(struct ipt_rule); i++) {
		if (hyper_setup_iptables_rule(rules[i])<0) {
			return;
		}
	}
}

int hyper_setup_container_portmapping(struct hyper_container *c, struct hyper_pod *pod)
{
	if (pod->w_num == 0) {
		return 0;
	}

	if (c->ports_num == 0) {
		return 0;
	}

	int i = 0, j = 0;
	char rule[128] = {0};

	for (i=0; i<c->ports_num; i++) {
		sprintf(rule, "-p %s -m %s --dport %d -j REDIRECT --to-ports %d",
			c->ports[i].protocol,
			c->ports[i].protocol,
			c->ports[i].host_port,
			c->ports[i].container_port);
		struct ipt_rule rediect_rule = {
			.table = "nat",
			.op = "-I",
			.chain = "hyperstart-PREROUTING",
			.rule = rule,
		};
		if (hyper_setup_iptables_rule(rediect_rule)<0) {
			fprintf(stderr, "setup rediect_rule '%s' failed\n", rule);
			return -1;
		}

		for (j=0; j<pod->w_num; j++) {
			sprintf(rule, "-s %s -p %s -m %s --dport %d -j ACCEPT",
				pod->white_cidrs[j],
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

	return 0;
}

void hyper_cleanup_container_portmapping(struct hyper_container *c, struct hyper_pod *pod)
{
	if (pod->w_num == 0) {
		return;
	}

	if (c->ports_num == 0) {
		return;
	}


	int i = 0, j = 0;
	char rule[128] = {0};

	for (i=0; i<c->ports_num; i++) {
		sprintf(rule, "-p %s -m %s --dport %d -j REDIRECT --to-ports %d", 
        c->ports[i].protocol,
        c->ports[i].protocol,
        c->ports[i].host_port,
        c->ports[i].container_port);
		struct ipt_rule rediect_rule = {
			.table = "nat",
			.op = "-D",
			.chain = "hyperstart-PREROUTING",
			.rule = rule,
		};
		if (hyper_setup_iptables_rule(rediect_rule)<0) {
			fprintf(stderr, "setup rediect_rule '%s' failed\n", rule);
		}

		for (j=0; j<pod->w_num; j++) {
			sprintf(rule, "-s %s -p %s -m %s --dport %d -j ACCEPT",
				pod->white_cidrs[j],
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
				fprintf(stderr, "setup accept_rule '%s' failed\n", rule);
			}
		}
		
	}
}
