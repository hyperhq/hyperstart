#ifndef _DVM_JSON_H_
#define _DVM_JSON_H_

#include "hyper.h"
#include "jsmn.h"

int hyper_parse_pod(struct hyper_pod *pod, char *json, int length);
struct hyper_exec *hyper_parse_execcmd(char *json, int length);
char *json_token_str(char *js, jsmntok_t *t);
int json_token_streq(char *js, jsmntok_t *t, char *s);
int hyper_parse_winsize(struct hyper_win_size *ws, char *json, int length);
int hyper_parse_write_file(struct hyper_writter *writter, char *json, int length);

#endif
