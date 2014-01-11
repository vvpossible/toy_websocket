#ifndef _SS_WS_SOCK_H
#define _SS_WS_SOCK_H

#include "gen.h"
#include "mem.h"
#include "log.h"

#define MAX_HOST_ADDR 64

typedef enum 
{
    SOCK_TYPE_TCP,
    SOCK_TYPE_UDP,
    SOCK_TYPE_SCTP,
    SOCK_TYPE_MAX,
} sock_type_t;

typedef enum
{
    SOCK_ACT_NO,
    SOCK_ACT_CLOSE,
    SOCK_ACT_MAX
} sock_action_t;


typedef struct sock_stats
{
    u32 tx_bytes;
    u32 rx_bytes;
    u32 cong_bytes;
} sock_stats_t;


typedef struct cong_block
{
    list_head_t cong_list;
    s8* buf;
    s32 len;
} cong_block_t;

/* socket control block */
struct sock_ops;
typedef struct sock_cb
{
    s32 sock_fd;
    s8 src_addr[MAX_HOST_ADDR];
    u16 src_port;
    list_head_t cong_q_head;
    list_head_t sk_cb_list;
    sock_stats_t stats;
    struct sock_ops* ops;
    void* priv;
} sock_cb_t;


/* socket call backs */
typedef struct sock_cb_ops
{
    s16 (*on_bind)(s32 fd);
    s16 (*on_listen)(s32 fd);
    s16 (*on_create)(sock_cb_t*, sock_action_t*);
    s16 (*on_recv)(void*, s8*, s32, sock_action_t*);
    s16 (*on_sent)(void*, sock_action_t*);
    s16 (*on_close)(void*);
    s16 (*on_error)(void*, sock_action_t*);
} sock_cb_ops_t;

/* service provided by socket layer */
typedef struct sock_ops
{
    s16 (*send)(sock_cb_t*, s8*, s32);
    s16 (*recv)(sock_cb_t* recv, s8*, s32*);
    s16 (*stats)(sock_cb_t*, s8 flag, sock_stats_t* stats);
    s16 (*reset_stats)(sock_cb_t*, s8 flag);
    s16 (*close)(sock_cb_t*, s8 flag);
} sock_ops_t;

typedef struct sock_control_point
{
    sock_type_t type;
    s8 init;
    s8 host[MAX_HOST_ADDR];
    s16 port;
    sock_cb_ops_t* cb_ops;
    sock_ops_t* ops;

    s32 num_conns;
    sock_stats_t stats;

    /* keep all socket control block in a list */
    list_head_t sk_cb_head;     

    s32 epoll_fd;
    s64 data;
    s16 (*sock_start)();
    s16 (*sock_stop)();

    s16 stop;

} sock_cp_t;

//////// tcp sock implementation /////////

s16 sock_init(sock_type_t type, s8* host, s16 port);
s16 sock_reg_callback(sock_cb_ops_t* cb_ops);
s16 sock_server_start();
s16 sock_server_stop();

#endif
