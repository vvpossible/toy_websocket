#ifndef _SS_WSOCK_H
#define _SS_WSOCK_H

#include "gen.h"
#include "sock.h"
#include "ws_parse.h"

typedef enum
{ 
    WS_SESS_AWAIT_HS,
    WS_SESS_EST,
    WS_SESS_CLOSING,
    WS_SESS_MAX,
} ws_sess_state_t;


#define ON_SOCK_ERR 0x1
#define ON_SOCK_CLOSE 0x2

struct ws_app_ops;
typedef struct ws_app
{
    list_head_t list;
    s8* name;
    s8* ver;
    s8* desc;
    u32 sub_events;
    struct ws_app_ops* ops;
} ws_app_t;

struct wsock_ops;
typedef struct ws_session
{
    struct wsock_ops* ops;

    ws_parse_ctl_t* p_ctl;
    ws_sess_state_t state;

    list_head_t list;
    sock_cb_t* sk_cb;

} ws_sess_t;


typedef struct wsock_ops
{
    s16 (*send)(ws_sess_t*, s8*, s32);
    s16 (*recv)(ws_sess_t*, s8*, s32*);
    s16 (*close)(ws_sess_t*, s8 flag);
} wsock_ops_t;


typedef struct ws_app_ops
{
    s16 (*init)(ws_app_t*);
    s16 (*deinit)(ws_app_t*);
    s16 (*recv)(ws_sess_t* sess, s8* data, s32 len);
    s16 (*notify)(ws_sess_t* sess, s32 evt, void* event);
    s16 (*close)(ws_sess_t* sess);
} ws_app_ops_t;


typedef struct wsock_cp
{
    s8 init;
    /* service provided by web socket layer */
    wsock_ops_t* ops;
    /* registered application module */
    list_head_t wsock_app_head;
    /* keep all session in list */
    list_head_t wsock_sess_head;

    s32 num_sess;

} wsock_cp_t;


s16 wsock_init(s8* host, s16 port);
s16 wsock_reg_app(ws_app_t* app);
s16 wsock_dereg_app(ws_app_t* app);

#endif
