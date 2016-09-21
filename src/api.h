#ifndef _HYPERSTART_API_H_
#define _HYPERSTART_API_H_

#define APIVERSION 4242

enum {
	GETVERSION,
	STARTPOD,
	GETPOD,
	STOPPOD_DEPRECATED,
	DESTROYPOD,
	RESTARTCONTAINER,
	EXECCMD,
	CMDFINISHED,
	READY,
	ACK,
	ERROR,
	WINSIZE,
	PING,
	PODFINISHED,
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
 * stream message format
 * | stream sequence | length  | payload (length-12)     |
 * | . . . . . . . . | . . . . | . . . . . . . . . . . . |
 * 0                 8         12                        length
 */
#define STREAM_HEADER_SIZE		12
#define STREAM_HEADER_LENGTH_OFFSET	8

#endif /* _HYPERSTART_API_H_ */
