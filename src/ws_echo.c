#include "sock.h"
#include "wsock.h"
#include "mem.h"
#include "log.h"
#include "gen.h"
#include <mcheck.h>

static s16 ws_echo_init(ws_app_t* app)
{
    dbg(WS_DBG, "init app global variable here.\n");
    return rok;
}

static s16 ws_echo_deinit(ws_app_t* app)
{
    dbg(WS_DBG, "destroy app global variable here.\n");
    return rok;
}

static s16 ws_echo_recv(ws_sess_t* sess, s8* data, s32 len)
{
    dbg(WS_DBG, "receive data from session [%p].\n", sess);

    sess->ops->send(sess, data, len);

    //    sess->ops->close(sess, 0);

    return rok;
}

static s16 ws_echo_notify(ws_sess_t* sess, s32 evt, void* event)
{
    dbg(WS_DBG, "we are notified event[%d] on session[%p]\n", evt, sess);

    return rok;
}

static s16 ws_echo_close(ws_sess_t* sess)
{
    dbg(WS_DBG, "web socket session [%p] is going away.\n", sess);
    return rok;
}

static ws_app_ops_t ws_echo_ops =
{
    .init = ws_echo_init,
    .deinit = ws_echo_deinit,
    .recv = ws_echo_recv,
    .notify = ws_echo_notify,
    .close = ws_echo_close,
};

static ws_app_t ws_echo = 
{
    .name = "ws_echo",
    .ver = "0.0.1",
    .desc = "echo what we got",
    .sub_events = ON_SOCK_ERR,
    .ops = &ws_echo_ops
};


int main(int argc, char** argv)
{
    s16 ret = rok;

    mtrace();

    file_log_cfg_t cfg;
    cfg.fname = "ws_log";
    cfg.sz_limit = 1024*1024;     
    cfg.file_inst_limit = 5;

    ret = log_init(0, &cfg);
    if(ret != rok)
        goto _err;

    ret = mem_init();
    if(ret != rok)
        goto _err;

    if(argc < 3) return -1;

    ret = wsock_init(argv[1], atoi(argv[2]));
    if(ret != rok)
    {
        dbg(WS_ERR, "failed to init web socket.\n");
        goto _err1;
    }

    ret = wsock_reg_app(&ws_echo);
    if(ret != rok)
    {
        dbg(WS_ERR, "failed to register ws_echo_app.\n");
        goto _err1;
    }

    ret = sock_server_start();
    if(ret != rok)
    {
        dbg(WS_ERR, "failed to start socket server.\n");
    }

 _err1:
    mem_deinit();
    log_deinit();

 _err:
    return ret;    
}
