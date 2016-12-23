#ifndef _HYPERSTART_API_H_
#define _HYPERSTART_API_H_

// when APIVERSION < 1000000, the version MUST be exactly matched on both sides
#define APIVERSION 4243

// control command id
enum {
	GETVERSION,			// 0
	STARTPOD,
	GETPOD_DEPRECATED,
	STOPPOD_DEPRECATED,
	DESTROYPOD,
	RESTARTCONTAINER_DEPRECATED,	// 5
	EXECCMD,
	CMDFINISHED_DEPRECATED,
	READY,
	ACK,
	ERROR,				// 10
	WINSIZE,
	PING,
	PODFINISHED_DEPRECATED,
	NEXT,
	WRITEFILE,			// 15
	READFILE,
	NEWCONTAINER,
	KILLCONTAINER,
	ONLINECPUMEM,
	SETUPINTERFACE,			// 20
	SETUPROUTE,
	REMOVECONTAINER,
	PROCESSASYNCEVENT,
	SIGNALPROCESS,
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
