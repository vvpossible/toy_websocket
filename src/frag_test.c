#include "sock.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

#define min(a, b) ((a>b)?(b):(a))

const s8* buf = "GET /chat HTTP/1.1\r\n\
Host:   10.0.2.15\r\n\
Upgrade:websocket\r\n\
CONNECTION: upgrade\r\n\
Sec-WebSocket-Key: ddfsdfsfsasdf==sdfdfsdfadfsdfsfd\r\n\
Sec-WebSocket-Version: 13\r\n\
Origin: localhost\r\n\
Sec-WebSocket-Protocol: localtest\r\n\
Sec-WebSocket-Extensions: xxxxxxxx;xxxx\r\n\r\n";

s8 ws_frame[] = { 0x01 ,0xfe ,0x00 ,0xd0 ,0xd9 ,0x15 ,0xa0 ,0x3f ,0x8e ,0x70 ,0xc2 ,0x6c ,0xb6 ,0x76 ,0xcb ,0x5a ,0xad ,0x35 ,0xd2 ,0x50 ,0xba ,0x7e ,0xd3 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e};

s8 ws_frame1[] = { 0x00 ,0xfe ,0x00 ,0xd0 ,0xd9 ,0x15 ,0xa0 ,0x3f ,0x8e ,0x70 ,0xc2 ,0x6c ,0xb6 ,0x76 ,0xcb ,0x5a ,0xad ,0x35 ,0xd2 ,0x50 ,0xba ,0x7e ,0xd3 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e};

s8 ws_frame2[] = { 0x00 ,0xfe ,0x00 ,0xd0 ,0xd9 ,0x15 ,0xa0 ,0x3f ,0x8e ,0x70 ,0xc2 ,0x6c ,0xb6 ,0x76 ,0xcb ,0x5a ,0xad ,0x35 ,0xd2 ,0x50 ,0xba ,0x7e ,0xd3 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e};

s8 ws_frame3[] = { 0x80 ,0xfe ,0x00 ,0xd0 ,0xd9 ,0x15 ,0xa0 ,0x3f ,0x8e ,0x70 ,0xc2 ,0x6c ,0xb6 ,0x76 ,0xcb ,0x5a ,0xad ,0x35 ,0xd2 ,0x50 ,0xba ,0x7e ,0xd3 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e};

s8 ws_frame4[] = {
    0x01 ,0xfe ,0x00 ,0xd0 ,0xd9 ,0x15 ,0xa0 ,0x3f ,0x8e ,0x70 ,0xc2 ,0x6c ,0xb6 ,0x76 ,0xcb ,0x5a ,0xad ,0x35 ,0xd2 ,0x50 ,0xba ,0x7e ,0xd3 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e,
    0x00 ,0xfe ,0x00 ,0xd0 ,0xd9 ,0x15 ,0xa0 ,0x3f ,0x8e ,0x70 ,0xc2 ,0x6c ,0xb6 ,0x76 ,0xcb ,0x5a ,0xad ,0x35 ,0xd2 ,0x50 ,0xba ,0x7e ,0xd3 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e,
    0x00 ,0xfe ,0x00 ,0xd0 ,0xd9 ,0x15 ,0xa0 ,0x3f ,0x8e ,0x70 ,0xc2 ,0x6c ,0xb6 ,0x76 ,0xcb ,0x5a ,0xad ,0x35 ,0xd2 ,0x50 ,0xba ,0x7e ,0xd3 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e,
0x80 ,0xfe ,0x00 ,0xd0 ,0xd9 ,0x15 ,0xa0 ,0x3f ,0x8e ,0x70 ,0xc2 ,0x6c ,0xb6 ,0x76 ,0xcb ,0x5a ,0xad ,0x35 ,0xd2 ,0x50 ,0xba ,0x7e ,0xd3 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e ,0xf8 ,0x34 ,0x81 ,0x1e
};

int main(int argc, char** argv)
{
    struct sockaddr_in serv_addr;
    struct sockaddr_in local_addr;

    s16 ret;

    s32 fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
        return rfail;

    s32 option = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    bzero(&serv_addr, 0);
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_port=htons(8080);

    bzero(&local_addr, 0);
    local_addr.sin_family=AF_INET;
    local_addr.sin_port=htons(31111);

    ret = inet_aton("10.0.2.15", &local_addr.sin_addr);
    if(ret < 0)
        return rfail;

    ret = bind(fd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr));
    if(ret < 0)
        return rfail;

    ret = inet_aton("10.0.2.15", &serv_addr.sin_addr);
    ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr));
    if(ret < 0)
        return rfail;

    s32 total = 0;
    s32 len;

    while(total < strlen(buf))
    {
        len = (1+rand()) % 25;
        printf("send %d bytes =====>\n", len);

        write(0, buf + total, len);

        printf("\n===============\n");

        len = send(fd, buf+total, len ,0);

        total += len;

        sleep(1);
    }

    s32 rc = 0;
    s8 recv_buf[1024];

    memset(recv_buf, 0 , 1024);
    rc = recv(fd, recv_buf, sizeof(recv_buf), 0);
    printf("%s\n", recv_buf);

    int x = 1;
    int x1 = 0;
    char c;

    printf("1st fragment frame\n");
    total = 0;

    if(x)
    {
        while(total < sizeof(ws_frame))
        {
            len = min((1+rand()) % 50, sizeof(ws_frame) - total);

            len = send(fd, ws_frame+total, len ,0);
            printf("send %d bytes =====>\n", len);

            total += len;
            if(x1)
                scanf("%c", &c);
            else
                sleep(1);
        }

        printf("total bytes: %d. total sent : %d\n", sizeof(ws_frame), total);
    }
    else
        send(fd, ws_frame, sizeof(ws_frame), 0);

    printf("2nd fragment frame\n");
    total = 0;
    if(x)
    {
        while(total < sizeof(ws_frame1))
        {
            len = min((1+rand()) % 30, sizeof(ws_frame1) - total);

            len = send(fd, ws_frame1+total, len ,0);
            printf("send %d bytes =====>\n", len);
            total += len;

            if(x1)
                scanf("%c", &c);
            else
                sleep(1);
        }
        printf("total bytes: %d. total sent : %d\n", sizeof(ws_frame1), total);
    }
    else
        send(fd, ws_frame1, sizeof(ws_frame1), 0);

    printf("3rd fragment frame\n");
    total = 0;
    if(x)
    {
        while(total < sizeof(ws_frame2))
        {
            len = min((1+rand()) % 46, sizeof(ws_frame2) - total);
            len = send(fd, ws_frame2+total, len ,0);
            printf("send %d bytes =====>\n", len);
            total += len;

            if(x1)
                scanf("%c", &c);
            else
                sleep(1);
        }
        printf("total bytes: %d. total sent : %d\n", sizeof(ws_frame2), total);
    }
    else
        send(fd, ws_frame2, sizeof(ws_frame2), 0);

    printf("4th fragment frame\n");
    total = 0;
    if(x)
    {
        while(total < sizeof(ws_frame3))
        {
            len = min((1+rand()) % 69, sizeof(ws_frame3) - total);
            len = send(fd, ws_frame3+total, len ,0);
            printf("send %d bytes =====>\n", len);
            total += len;

            if(x1)
                scanf("%c", &c);
            else
                sleep(1);
        }
        printf("total bytes: %d. total sent : %d\n", sizeof(ws_frame3), total);
    }
    else
        send(fd, ws_frame3, sizeof(ws_frame3), 0);


    printf("TCP and Websockt fragment.\n");
    total = 0;
    if(x)
    {
        while(total < sizeof(ws_frame4))
        {
            len = min((1+rand()) % 69, sizeof(ws_frame4) - total);
            len = send(fd, ws_frame4+total, len ,0);
            printf("send %d bytes =====>\n", len);
            total += len;

            if(x1)
                scanf("%c", &c);
            else
                sleep(1);
        }
        printf("total bytes: %d. total sent : %d\n", sizeof(ws_frame4), total);
    }
    else
        send(fd, ws_frame4, sizeof(ws_frame4), 0);

    bzero(recv_buf, sizeof(recv_buf));
    rc = recv(fd, recv_buf, sizeof(recv_buf), 0);
    printf("%s\n", recv_buf);

    return rok;
}
