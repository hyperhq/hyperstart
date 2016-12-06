#ifndef _HYPERSTART_API_H_
#define _HYPERSTART_API_H_

#define APIVERSION 4242

// control command id
enum {
	GETVERSION,
	STARTPOD,
	GETPOD_DEPRECATED,
	STOPPOD_DEPRECATED,
	DESTROYPOD,
	RESTARTCONTAINER_DEPRECATED,
	EXECCMD,
	CMDFINISHED_DEPRECATED,
	READY,
	ACK,
	ERROR,
	WINSIZE,
	PING,
	PODFINISHED_DEPRECATED,
	NEXT,
	WRITEFILE,
	READFILE,
	NEWCONTAINER,
	KILLCONTAINER,
	ONLINECPUMEM,
	SETUPINTERFACE,
	SETUPROUTE,
	REMOVECONTAINER,
};

/*
 * control message format
 * | ctrl id | length  | payload (length-8)      |
 * | . . . . | . . . . | . . . . . . . . . . . . |
 * 0         4         8                         length
 */
#define CONTROL_HEADER_SIZE		8
#define CONTROL_HEADER_LENGTH_OFFSET	4

/*
 * stream message format
 * | stream sequence | length  | payload (length-12)     |
 * | . . . . . . . . | . . . . | . . . . . . . . . . . . |
 * 0                 8         12                        length
 */
#define STREAM_HEADER_SIZE		12
#define STREAM_HEADER_LENGTH_OFFSET	8

#endif /* _HYPERSTART_API_H_ */
