#include "sock.h"
#include "mem.h"
#include "sha1.h"
#include "wsock.h"
#include "ws_parse.h"

extern s32 base64_encode(u8*, s32, u8*);

static wsock_cp_t wsock_control_point;
static wsock_cp_t* wsock_cp = &wsock_control_point;

static s16 wsock_send(ws_sess_t*, s8*, s32);
static s16 wsock_recv(ws_sess_t*, s8*, s32*);
static s16 wsock_close(ws_sess_t*, s8);
static s16 ws_proc_msg(ws_sess_t* sess, s8* data, s32 len);
static void dump_raw_web_sock_data(s8* data, s32 len);
static s16 ws_send_frame(ws_sess_t* sess, s8* data, s32 len, u32 op_code);

static wsock_ops_t wsock_ops =
{
    .send = wsock_send,
    .recv = wsock_recv,
    .close = wsock_close,
};

static s16 wsock_send(ws_sess_t* sess, s8* data, s32 len)
{
    s16 ret ;

    if(sess->state != WS_SESS_EST)
    {
        dbg(WS_ERR, "session is not established yet.\n");
        return rfail;
    }

    ret = ws_send_frame(sess, data, len, WS_OP_CODE_TEXT);

    if(ret != rok)
    {
        dbg(WS_ERR, "failed to send websocket message.\n");
        return rfail;
    }

    return rok;
}

static s16 wsock_recv(ws_sess_t* sess, s8* data, s32* len)
{
    sock_cb_t* sk_cb = sess->sk_cb;
    if(sess->state != WS_SESS_EST)
    {
        dbg(WS_ERR, "session is not established yet.\n");
        return rfail;
    }
    return sk_cb->ops->recv(sk_cb, data, len);
}

static s16 wsock_close(ws_sess_t* sess, s8 flag)
{
    if(sess->state == WS_SESS_EST)
    {
        sess->state = WS_SESS_CLOSING;
        ws_send_frame(sess, NULL, 0, WS_OP_CODE_CLOSE);
        return rok;
    }
    else if(sess->state == WS_SESS_CLOSING)
        return rok;
    else 
        return rfail;
}

///////////////web socket rfc6455 impl////////////////
static s16 wsock_on_create(sock_cb_t* sk_cb, sock_action_t* act);
static s16 ws_hand_shake(ws_sess_t* sess, s8* data, s32 len);
static s16 wsock_on_recv(void* session, s8* data, s32 len, sock_action_t* act);
static s16 wsock_on_close(void* session);
static s16 wsock_on_error(void* session, sock_action_t* act);
static s16 ws_validate_req(ws_sess_t* sess);
static void get_sec_key(ws_sess_t* sess, u8* out, s32 len);
static s16 ws_build_http_rsp(ws_sess_t* sess, s8** rsp, s32* len, u32 code);


static sock_cb_ops_t wsock_callbacks = 
{
    .on_bind = NULL,
    .on_listen = NULL,
    .on_create = wsock_on_create,
    .on_recv = wsock_on_recv,
    .on_close = wsock_on_close,
    .on_error = wsock_on_error,
};

static s16 wsock_on_create(sock_cb_t* sk_cb, sock_action_t* act)
{
    /* todo: filter based on policy */
    ws_sess_t* sess = mem_alloc(sizeof(ws_sess_t));

    if(!sess)
    {
        dbg(WS_ERR, "out of memory for new connection.\n");
        *act = SOCK_ACT_CLOSE;
        return rfail;
    }

    bzero(sess, sizeof(ws_sess_t));

    dbg(WS_DBG, "alloc new web socket session.\n");

    sk_cb->priv = sess;
    sess->sk_cb = sk_cb;

    sess->ops = wsock_cp->ops;

    list_add_tail(&(sess->list), &(wsock_cp->wsock_sess_head));

    wsock_cp->num_sess++;

    sess->p_ctl = alloc_parse_ctl();

    if(!sess->p_ctl)
    {
        dbg(WS_ERR, "out of memory for parser.\n");
        *act = SOCK_ACT_CLOSE;
        return rfail;
    }

    return rok;
}

static s16 ws_validate_req(ws_sess_t* sess)
{
    s16 i;
    header_t* hd;

    for( i = 0 ; i < HDR_MAX ; i++)
    {
        hd = sess->p_ctl->parser.hdr_tbl + i;
        if(hd->is_opt == false && hd->pres == false)
        {
            dbg(WS_ERR, "mandatory header [%s] is not present.\n", hd->name);
            return rfail;
        }
    }

    return rok;
}

static void get_sec_key(ws_sess_t* sess, u8* out, s32 len)
{
    s8* magic="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    s8* key = ws_hdr_val(sess, HDR_SEC_WS_KEY);
    s32 key_len = ws_hdr_len(sess, HDR_SEC_WS_KEY);
    s32 i;
    u8 sha_res[20];
    u8 input[128];

    bzero(out, len);
    bzero(input, sizeof(input));

    memcpy(input, key, key_len);
    memcpy(input+key_len, magic, strlen(magic));

    dbg(WS_DBG, "receive key: %s len: %d\n", input, key_len+strlen(magic));

    SHA1Context sha;
    SHA1Reset(&sha);
    SHA1Input(&sha, (const u8*)input, key_len + strlen(magic));

    assert(SHA1Result(&sha));

    dbg(WS_DBG, "%8x %8x %8x %8x %8x\n",
                sha.Message_Digest[0],
                sha.Message_Digest[1],
                sha.Message_Digest[2],
                sha.Message_Digest[3],
                sha.Message_Digest[4]);

    for(i = 0 ; i < 5 ; i++)
    {
        u8* p = (u8*)&(sha.Message_Digest[i]);
        sha_res[4*i] = p[3];
        sha_res[4*i+1]= p[2];
        sha_res[4*i+2] = p[1];
        sha_res[4*i+3] = p[0];
    }

    base64_encode(sha_res, 20, out);

    dbg(WS_DBG, "generate key: %s\n", out);

    return;
}

static s16 ws_build_http_rsp(ws_sess_t* sess, s8** rsp, s32* len, u32 code)
{
    s8* buf;
    s32 total_len = 0;

    buf = mem_alloc(MAX_HTTP_RSP);
    if(!buf)
    {
        dbg(WS_ERR, "no memory for http response.\n");
        return rfail;
    }

    total_len += sprintf(buf, "%s %d %s\r\n", HTTP_VER, code, get_rphrase(code));

    if(code == 101)
    {
        total_len += sprintf(buf + total_len, "Upgrade: websocket\r\n");
        total_len += sprintf(buf + total_len, "Connection: Upgrade\r\n");
        u8 key[128];
        get_sec_key(sess, key, 128);

        total_len += sprintf(buf + total_len, "Sec-WebSocket-Accept: %s\r\n", key);
    }

    total_len += sprintf(buf + total_len, "\r\n");

    *rsp = buf;
    *len = total_len;

    return rok;
}

static s16 ws_hand_shake(ws_sess_t* sess, s8* data, s32 len)
{
    s16 ret = rok;
    s8* rsp = NULL;
    s32 rsp_len;

    assert(sess && data && len);

    parse_act_t act = ws_parse(sess->p_ctl, data, len);

    if(act == PARSE_ACT_OK)
    {
        ret = ws_validate_req(sess);
        if(ret != rok)
        {
            dbg(WS_ERR, "header validation failed.\n");
            goto _out;
        }
        
        ret = ws_build_http_rsp(sess, &rsp, &rsp_len, 101);
        if(ret != rok)
        {
            dbg(WS_ERR, "failed to build handshake response.\n");
            goto _out;
        }
        sess->sk_cb->ops->send(sess->sk_cb, rsp, rsp_len);
        mem_free(rsp);
        sess->state = WS_SESS_EST;
        /* protocol switched */
        free_parse_ctl(sess->p_ctl);
        sess->p_ctl = alloc_parse_ctl();
        if(!sess->p_ctl)
        {
            dbg(WS_ERR, "failed to alloc memory.\n");
            return rfail;
        }
        sess->p_ctl->parser.state = PARSE_FRAME_CTL;
        sess->p_ctl->type = TYPE_WEBSOCK;
        INIT_LIST_HEAD(&(sess->p_ctl->parser.frag_frame_head));
        INIT_LIST_HEAD(&(sess->p_ctl->parser.payload_head));
        return rok;
    }
    else if(act == PARSE_ACT_MORE_DATA)
    {
        dbg(WS_DBG, "wait for more data.\n");
        return rok;
    }
    else if(act == PARSE_ACT_ERROR)
    {
        dbg(WS_ERR, "failed to parse data.\n");

        ret = ws_build_http_rsp(sess, &rsp, &rsp_len, 400);
        if(ret != rok)
        {
            dbg(WS_ERR, "failed to build 400 response.\n");
            goto _out;
        }
        sess->sk_cb->ops->send(sess->sk_cb, rsp, rsp_len);
        mem_free(rsp);
        return rfail;
    }
 _out:
    return ret;
}

static void dump_raw_web_sock_data(s8* data, s32 len)
{
    s32 i,n;
    s8* buf;

    buf = mem_alloc(len*3+1);
    if(!buf)
        return;

    bzero(buf, len*3+1);

    dbg(WS_DBG, "dump websocket data >>>>\n");
    for(i = 0, n = 0 ; i < len ; i++)
    {
        n += sprintf(buf+n, "%.2x ", *((u8*)data +i));
    }
    dbg(WS_DBG, "%s\n", buf);

    mem_free(buf);

    return;
}

static s16 ws_send_frame(ws_sess_t* sess, s8* data, s32 len, u32 op_code)
{
    s8* msg_buf;
    s32 msg_len;
    s16 ret = rok;

    sock_cb_t* sk_cb = sess->sk_cb;
    ws_frame_t frame;
    bzero(&frame, sizeof(ws_frame_t));

    frame.fin = 1;
    frame.rsv = 0;
    frame.op_code = op_code;
    frame.mask = 0;
    if(len > 125)
    {
        frame.ext_len = len;

        if(len > 0xFFFF)
            frame.len = 0x7F;
        else
            frame.len = 0x7E;
    }
    else
        frame.len = len;

    frame.payload = data;

    ret = ws_build_frame(&frame, &msg_buf, &msg_len);

    if(ret != rok)
    {
        dbg(WS_ERR, "failed to send websocket message.\n");
        return rfail;
    }

    ret = sk_cb->ops->send(sk_cb, msg_buf, msg_len);
    if(ret != rok)
    {
        dbg(WS_ERR, "failed to send websocket message.\n");
        mem_free(msg_buf);
        return rfail;
    }

    //dump_raw_web_sock_data(msg_buf, msg_len);
    mem_free(msg_buf);
    
    return rok;
}

static s16 ws_proc_msg(ws_sess_t* sess, s8* data, s32 len)
{
    ws_payload_t *payload, *tmp;

    assert(sess && data && len);

    dump_raw_web_sock_data(data, len);

    parse_act_t act = ws_parse(sess->p_ctl, data, len);

    if(act == PARSE_ACT_OK)
    {
        list_for_each_entry_safe(payload, tmp, &(sess->p_ctl->parser.payload_head), payload_list)
        {
            if(sess->state == WS_SESS_CLOSING)
            {
                dbg(WS_DBG, "upper layer has told us to shutdown, don't send the message.\n");
            }
            else
            {
                dbg(WS_DBG, "receive one frame from ws_socket op[%d].\n", payload->op_code);
            
                if(payload->op_code > WS_OP_CODE_BIN)
                {
                    dbg(WS_WARN, "this is a contorl frame.\n");
                    switch(payload->op_code)
                    {
                    case WS_OP_CODE_CLOSE:
                        if(sess->state == WS_SESS_CLOSING)
                        {
                            dbg(WS_DBG, "we have already sent the CLOSE frame.\n");
                        }
                        else if(sess->state == WS_SESS_EST)
                        {
                            dbg(WS_DBG, "receive CLOSE frame from peer.\n");
                            ws_send_frame(sess, payload->data, payload->len, WS_OP_CODE_PONE);
                            sess->state = WS_SESS_CLOSING;
                        }
                        break;
                    case WS_OP_CODE_PING:
                        dbg(WS_DBG, "heartbeat message from peer, reply with PONE.\n");
                        ws_send_frame(sess, payload->data, payload->len, WS_OP_CODE_CLOSE);

                        break;
                    default:
                        assert(false);
                    }
                }
                else
                {
                    dbg(WS_DBG, "this is a data frame.\n");

                    ws_app_t* app;
                    list_for_each_entry(app, &(wsock_cp->wsock_app_head), list) 
                    {
                        if(app->ops->recv(sess, payload->data, payload->len) == rok)
                        {
                            dbg(WS_DBG, "handled by app: %s ver: %s.\n", app->name, app->ver);
                            break;
                        }
                    }
                }
            }
            list_del(&(payload->payload_list));
            mem_free(payload->data);
            payload->data = NULL;
            payload->len = 0;
            mem_free(payload);
        }
        if(sess->state == WS_SESS_CLOSING)
            return rfail;
        return rok;
    }
    else if(act == PARSE_ACT_MORE_DATA)
    {
        dbg(WS_DBG, "wait for more data to come.\n");
        return rok;
    }
    else 
    {
        assert(act == PARSE_ACT_ERROR);
        dbg(WS_ERR, "failed to parse websocket data.\n");
        return rfail;
    }
}

static s16 wsock_on_recv(void* session, s8* data, s32 len, sock_action_t* act)
{
    s16 ret = rok;

    ws_sess_t* sess = (ws_sess_t*)session;

    if(sess->state == WS_SESS_AWAIT_HS)
    {
        dbg(WS_DBG, "hand shake message from client.\n");

        ret = ws_hand_shake(sess, data, len);

        if(ret != rok)
        {
            dbg(WS_ERR, "failed to do handshake.\n");
            goto _out;
        }
    }
    else /* web socket established */
    {
        dbg(WS_DBG, "websocket session %p recv msg.\n", sess);

        ret = ws_proc_msg(sess, data, len);

        if(ret != rok)
        {
            dbg(WS_ERR, "failed to process message.\n");
            goto _out;
        }
    }
    return rok;

 _out:
    *act = SOCK_ACT_CLOSE;
    return ret;
}

static s16 wsock_on_close(void* session)
{
    ws_sess_t* sess = (ws_sess_t*)session;

    dbg(WS_DBG, "socket layer notify us to close\n");

    ws_app_t* app;
    list_for_each_entry(app, &(wsock_cp->wsock_app_head), list) 
    {
        if(app->ops->close(sess) == rok)
            break;
    }

    if(sess->p_ctl)
    {
        free_parse_ctl(sess->p_ctl);
    }
    /* free ws session related memory */
    list_del(&(sess->list));

    wsock_cp->num_sess--;
    assert(wsock_cp->num_sess >= 0);

    dbg(WS_DBG, "ws session %p is freed.\n", sess);

    mem_free(sess);

    return rok;
}

static s16 wsock_on_error(void* session, sock_action_t* act)
{
    ws_sess_t* sess = (ws_sess_t*)session;

    dbg(WS_DBG, "socket layer notify us that error happened\n");

    ws_app_t* app;
    list_for_each_entry(app, &(wsock_cp->wsock_app_head), list) 
    {
        if(app->sub_events & ON_SOCK_ERR)
            app->ops->notify(sess, ON_SOCK_ERR, NULL);
    }

    *act = SOCK_ACT_CLOSE;

    return rok;
}

//////////////////////////////////////////////////////

s16 wsock_init(s8* host, s16 port)
{
    s16 ret;

    ret = sock_init(SOCK_TYPE_TCP, host, port);
    if(ret != rok)
    {
        dbg(WS_ERR, "failed to init TCP socket.\n");
        return ret;
    }
    ret = sock_reg_callback(&wsock_callbacks);

    wsock_cp->ops = &wsock_ops;

    INIT_LIST_HEAD(&(wsock_cp->wsock_app_head));
    INIT_LIST_HEAD(&(wsock_cp->wsock_sess_head));

    wsock_cp->num_sess = 0;
    wsock_cp->init = true;

    return ret;
}

s16 wsock_reg_app(ws_app_t* app)
{
    s16 ret;

    assert(app);

    ret = app->ops->init(app);
    if(ret != rok)
    {
        dbg(WS_ERR, "app %s-%s failed to init.\n", app->name, app->ver);
        return rfail;
    }
    /* exam duplicate */
    list_add_tail(&(app->list),&(wsock_cp->wsock_app_head)); 

    return rok;

}

s16 wsock_dereg_app(ws_app_t* app)
{
    s16 ret = rok;

    assert(app);

    if(app->ops && app->ops->deinit)
    {
        ret = app->ops->deinit(app);
        if(ret != rok)
        {
            dbg(WS_DBG, "app %s-%s failed to init.\n", app->name, app->ver);
            return rfail;
        }
    }
    
    list_del(&(app->list)); 

    return rok;
}

