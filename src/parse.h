#ifndef _PARSE_H_
#define _PARSE_H_

#include "hyper.h"
#include "jsmn.h"
#include "parson.h"

int hyper_parse_pod(struct hyper_pod *pod, char *json, int length);
struct hyper_exec *hyper_parse_execcmd(char *json, int length);
char *json_token_str(char *js, jsmntok_t *t);
int json_token_streq(char *js, jsmntok_t *t, char *s);
int hyper_parse_winsize(struct hyper_win_size *ws, char *json, int length);
int hyper_parse_file_command(struct file_command *cmd, char *json, int length);
struct hyper_container *hyper_parse_new_container(struct hyper_pod *pod, char *json, int length);
void hyper_free_container(struct hyper_container *c);
struct hyper_interface *hyper_parse_setup_interface(char *json, int length);
void hyper_free_interface(struct hyper_interface *iface);
int hyper_parse_setup_routes(struct hyper_route **routes, uint32_t *r_num, char *json, int length);
JSON_Value *hyper_json_parse(char *json, int length);

#endif
