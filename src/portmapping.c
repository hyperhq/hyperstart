#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "hyper.h"
#include "util.h"
#include "../config.h"

int hyper_init_iptables() 
{
	const char *cmd = "/sbin/modprobe iptable_filter iptable_nat xt_multiport xt_REDIRECT";
	fprintf(stdout, "command for init iptables is %s\n", cmd);

	int status = hyper_cmd(cmd);
	if (status < 0) {
		fprintf(stderr, "modprobe iptables exit unexpectedly, status %d\n", status);
	}

	return status
}

int hyper_insert_rule(struct ipt_rule rule)
{
	char check_cmd[512] = {0};
	char cmd[512] = {0};
	int check = -1;

	if rule.rule != NULL {
		sprintf(check_cmd, "/iptables -t %s -C %s %s", rule.table, rule.chain, rule.rule);
		sprintf(cmd, "/iptables -t %s %s %s %s", rule.table, rule.op, rule.chain, rule.rule);
	} else {
		sprintf(cmd, "/iptables -t %s %s %s", rule.table, rule.op, rule.chain);
	}

	if (strlen(check_cmd) > 0) {
		check =  hyper_cmd(check_cmd);
		fprintf(stdout, "check iptables '%s' status %d\n", check_cmd, status);
	}
	
	if check == 0 {
		fprintf(stdout, "iptables rule '%s' already exist\n", rule.rule);
		return 0;
	}

	int status = hyper_cmd(cmd);
	fprintf(stdout, "insert iptables '%s' status %d\n", cmd, status);
	if (status < 0) {
		fprintf(stderr, "insert iptables rule failed, status %d\n", status);
	}

	return status
}

// load iptables modules and initialize iptables chain
int hyper_setup_portmapping(struct hyper_pod *pod)
{
	if pod->w_num == 0 {
		return 0;
	}

	if (hyper_init_iptables() < 0) {
		fprintf(stderr, "modprobe iptables modules failed\n");
		return -1;
	}

	// "/iptables -t filter -N hyperstart-INPUT",
	// "/iptables -t nat -N hyperstart-PREROUTING",
	// "/iptables -t filter -I INPUT -j hyperstart-INPUT",
	// "/iptables -t nat -I PREROUTING -j hyperstart-PREROUTING",
	// "/iptables -t filter -A hyperstart-INPUT -j DROP ",
	// "/iptables -t nat -A hyperstart-PREROUTING -j RETURN"};
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
			.rule = "-j DROP",
		},
		{
			.table = "nat",
			.op = "-A",
			.chain = "hyperstart-PREROUTING",
			.rule = "-j RETURN",
		},
	}

	for(int i=0; i< sizeof(rules)/sizeof(struct ipt_rule); i++) {
		if (hyper_insert_rule(rules[i])<0) {
			fprintf(stderr, "insert iptables rule '%s' failed\n", rules[i].rule);
			return -1;
		}
	}

	return 0;
}

void hyper_cleanup_portmapping(struct hyper_pod *pod)
{
	int status = 0;

	if pod->w_num == 0 {
		return 0;
	}

	// const char* rules[] = {"/iptables -t filter -D hyperstart-INPUT -j DROP ",
	// 	"/iptables -t nat -D hyperstart-PREROUTING -j RETURN",
	// 	"/iptables -t filter -D INPUT -j hyperstart-DNPUT",
	// 	"/iptables -t nat -D PREROUTING -j hyperstart-PREROUTING",
	// 	"/iptables -t filter -F hyperstart-INPUT",
	// 	"/iptables -t nat -F hyperstart-PREROUTING",
	// 	"/iptables -t filter -X hyperstart-INPUT",
	// 	"/iptables -t nat -X hyperstart-PREROUTING",};

}

// iptables -t filter -I hyperstart-INPUT -s 0.0.0.0/0 -p tcp -m multiport --dports 80 -j ACCEPT
// iptables -t nat -I hyperstart-PREROUTING -p tcp -m tcp --dport 8080 -j REDIRECT --to-ports 80
int hyper_setup_container_portmapping(struct hyper_container *c, struct hyper_pod *pod)
{
	if pod->w_num == 0 {
		return 0;
	}

	if c->ports_num == 0 {
		return 0;
	}

	return 0;
}

int hyper_cleanup_container_portmapping(struct hyper_container *c, struct hyper_pod *pod)
{
	if pod->w_num == 0 {
		return 0;
	}

	if c->ports_num == 0 {
		return 0;
	}

	return 0;
}
