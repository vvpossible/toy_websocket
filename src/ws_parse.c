#include "ws_parse.h"
#include "mem.h"
#include "log.h"
#include <endian.h>

static parse_act_t ws_parse_websock(ws_parser_t* wsp, s8* data, s32 len);
static parse_act_t ws_parse_http(ws_parser_t* hp, s8* data, s32 len);
static s16 token_cmp(s8* begin, s8* end, s8* token);
static s16 token_case_cmp(s8* begin, s8* end, s8* token);
static void parse_request_line(ws_parser_t* hp);
static header_t* find_header(s8* tb, s8* te, header_t* tbl);
static s16 store_value(s8* tb, s8* te, header_t* h);
static void parse_http_headers(ws_parser_t* hp);
static void free_hdr_tbl(header_t* tbl);
static s16 agg_recv_data(ws_parser_t* parser, s8* data, s32 len); 
static s16 _parse_frame_ctl(ws_parser_t* wsp);
static s16 _parse_frame_ext_len(ws_parser_t* wsp);
static s16 _parse_frame_mask_key(ws_parser_t* wsp);
static s16 _parse_frame_payload(ws_parser_t* wsp);
static s16 queue_one_payload(ws_parser_t* wsp);
static void unmask_payload(ws_parser_t* wsp);

ws_parse_ctl_t* alloc_parse_ctl()
{
    ws_parse_ctl_t* p_ctl = mem_alloc(sizeof(ws_parse_ctl_t));

    if(p_ctl == NULL) return p_ctl;

    memset(p_ctl, 0, sizeof(ws_parse_ctl_t));

    return p_ctl;
}

void free_parse_ctl(ws_parse_ctl_t* p_ctl)
{
    ws_parser_t* wp = &(p_ctl->parser);        

    if(wp->buf)
    {
        mem_free(wp->buf);
        wp->buf = NULL;
    }

    if(p_ctl->type == TYPE_HTTP)
    {
        dbg(WS_DBG, "free http headers.\n");
        if(wp->hdr_tbl)
        {
            free_hdr_tbl(wp->hdr_tbl);
            wp->hdr_tbl = NULL;
        }
    }
    else
    {
        dbg(WS_DBG, "free websocket parse control block.\n");

        if(wp->frame != NULL)
        {
            dbg(WS_DBG, "free temporary frame.\n");
            if(wp->frame->payload)
                mem_free(wp->frame->payload);
            mem_free(wp->frame);
        }

        ws_payload_t *payload, *tmp;
        list_for_each_entry_safe(payload, tmp, &(p_ctl->parser.payload_head), payload_list)
        {
            dbg(WS_DBG, "free unhandled payload.\n");
            list_del(&(payload->payload_list));
            mem_free(payload->data);
            mem_free(payload);
        }

        ws_frame_t *frame, *tmp_fr;
        list_for_each_entry_safe(frame, tmp_fr, &(p_ctl->parser.frag_frame_head), frag_list)
        {
            dbg(WS_DBG, "free unhandled frame.\n");
            list_del(&(frame->frag_list));
            mem_free(frame->payload);
            mem_free(frame);
        }
    }

    mem_free(p_ctl);

    return;
}

s16 ws_build_frame(ws_frame_t* frame, s8** buf, s32* len)
{
    u16 val;
    s32 offset = 0 ;
    u16 ext_len = 0;
    u64 ext_len1 = 0;

    if(frame->len < 126)
    {
        *len = 2+frame->len;
    }
    else if(frame->len == 126)
    {
        *len = 4+frame->ext_len;
        ext_len = frame->ext_len;
    }
    else 
    {
        *len = 10+frame->ext_len;
        ext_len1 = frame->ext_len;
    }
        
    *buf = mem_alloc(*len);
    if(!*buf)
        return rfail;

    val = frame->fin << 15 | frame->rsv << 12
          | frame->op_code << 8 | frame->mask << 7 | frame->len;

    val = htobe16(val);
    memcpy(*buf+offset, &val, sizeof(val));
    offset += sizeof(val);

    if(ext_len)
    {
        ext_len = htobe16(ext_len);
        memcpy(*buf+offset, &ext_len, sizeof(ext_len));
        offset += sizeof(ext_len);
    }
    if(ext_len1)
    {
        ext_len1 = htobe64(ext_len1);
        memcpy(*buf+offset, &ext_len1, sizeof(ext_len1));
        offset += sizeof(ext_len1);
    }

    if(frame->payload)
        memcpy(*buf+offset, frame->payload, frame->ext_len? : frame->len);

    return rok;
}

s8* get_rphrase(u32 code)
{
    static http_rphrase_t phrase_tbl[] = 
    {
        {101, HTTP_101},
        {400, HTTP_400},
        {500, HTTP_500}
    };

    s32 i;
    for(i = 0 ; i < arr_size(phrase_tbl) ; i++)
    {
        if(phrase_tbl[i].code == code)
            return phrase_tbl[i].phrase;
    }
    return "unknown";
}

parse_act_t ws_parse(ws_parse_ctl_t* p_ctl, s8* data, s32 len)
{
    if(p_ctl->type == TYPE_HTTP)
    {
        dbg(WS_DBG, "parse http request.\n");
        return ws_parse_http(&(p_ctl->parser), data, len);
    }
    else if(p_ctl->type == TYPE_WEBSOCK)
    {
        dbg(WS_DBG, "parse websocket message.\n");
        return ws_parse_websock(&(p_ctl->parser), data, len);
    }
    else
    {
        dbg(WS_ERR, "invalid parser type.\n");
    }
    return PARSE_ACT_ERROR;
}

static void free_hdr_tbl(header_t* tbl)
{
    s32 i;
    for(i = 0 ; i < HDR_MAX ; i++)
    {
        if(tbl[i].pres == true)
        {
            mem_free(tbl[i].value.data);
            tbl[i].value.data = NULL;
            tbl[i].value.len = 0;
        }
    }
    mem_free(tbl);
}

static s16 agg_recv_data(ws_parser_t* parser, s8* data, s32 len) 
{
    s16 ret = rok;
    s8* tmp;

    if(parser->int_buf_len)
    {
        tmp = parser->buf;
        parser->buf = mem_alloc(parser->int_buf_len + len);
        if(!parser->buf)
        {
            dbg(WS_ERR, "no memory avail.\n");
            mem_free(tmp);
            ret = rfail;
            goto _out;
        }
        memcpy(parser->buf, tmp, parser->int_buf_len);
        memcpy(parser->buf + parser->int_buf_len, data, len);
        parser->int_buf_len += len;
        mem_free(tmp);
    }
    else
    {
        parser->buf = mem_alloc(len);
        if(!parser->buf)
        {
            dbg(WS_ERR, "no memory avail.\n");
            ret = rfail;
            goto _out;
        }
        memcpy(parser->buf, data, len);
        parser->int_buf_len = len;
    }

 _out:
    return ret;
}


static _frame_parse_func_t parse_func_tbl[] = 
{
    _parse_frame_ctl,
    _parse_frame_ext_len,
    _parse_frame_mask_key,
    _parse_frame_payload,
};

static s16 _parse_frame_ctl(ws_parser_t* wsp)
{
    u16 val = 0;

    if(!is_data_ready(wsp, WS_FRAME_CTL_LEN))
    {
        dbg(WS_DBG, "wait for more data.\n");
        wsp->act = PARSE_ACT_MORE_DATA;
        return rok;
    }

    wsp->frame = (ws_frame_t*)mem_alloc(sizeof(ws_frame_t));
    bzero(wsp->frame, sizeof(ws_frame_t));

    if(!wsp->frame)
    {
        dbg(WS_ERR, "no memory.\n");
        goto _err;
    }

    val = htobe16(*((u16*)ws_data(wsp)));

    ws_frame(wsp)->fin = val>>15;
    ws_frame(wsp)->rsv = val>>12 & 0x7;
    ws_frame(wsp)->op_code = val>>8 & 0xf;
    ws_frame(wsp)->mask = (val & 0xff)>>7;
    ws_frame(wsp)->len = val & 0x7f;


    if(ws_frame(wsp)->rsv != 0)
    {
        dbg(WS_ERR, "reserved bits are not zero [%x] [%d] .\n", val, ws_frame(wsp)->rsv);
        goto _err;
    }

    if((ws_frame(wsp)->op_code > WS_OP_CODE_BIN 
        && ws_frame(wsp)->op_code < WS_OP_CODE_CLOSE)
       || (ws_frame(wsp)->op_code > WS_OP_CODE_PONE))
    {
        dbg(WS_ERR, "unsupoorted operation code %d.\n", ws_frame(wsp)->op_code);
        goto _err;
    }

    if(ws_frame(wsp)->mask == 0)
    {
        dbg(WS_ERR, "client must use mask.\n");
        goto _err;
    }

    if(is_ctl_frame(ws_frame(wsp)))
    {
        if(ws_frame(wsp)->len > 125)
        {
            dbg(WS_ERR, "control frame is too long: %d", ws_frame(wsp)->len);
            goto _err;
        }
        if(!is_unfrag_frame(ws_frame(wsp)))
        {
            dbg(WS_ERR, "control frame can't be fragmented");
            goto _err;
        }
    }

    wsp->data_offset += WS_FRAME_CTL_LEN;
    wsp->act = PARSE_ACT_CONTINUE;
    wsp->state = PARSE_FRAME_LEN;
    return rok;

 _err:
    wsp->act = PARSE_ACT_ERROR;
    wsp->state = PARSE_DONE;

    return rfail;
}


static s16 _parse_frame_ext_len(ws_parser_t* wsp)
{
    if(ws_frame(wsp)->len == 0)
    {
        dbg(WS_WARN, "received one frame with len = 0.\n");
        wsp->act = PARSE_ACT_CONTINUE;
        wsp->state = PARSE_FRAME_MASK;
        return rok;
    }
    else if(ws_frame(wsp)->len == 126) /* 2 bytes ext */
    {
        if(!is_data_ready(wsp, WS_FRAME_EXT1_LEN))
        {
            dbg(WS_DBG, "wait for more data.\n");
            wsp->act = PARSE_ACT_MORE_DATA;
            return rok;
        }
        ws_frame(wsp)->ext_len = htobe16(*((u16*)(ws_data(wsp))));
        wsp->data_offset += WS_FRAME_EXT1_LEN;

        dbg(WS_DBG, "message len %lld\n", ws_frame(wsp)->ext_len);

        goto _cont;
    }
    else if(ws_frame(wsp)->len == 127) /* 8 bytes ext */
    {
        if(!is_data_ready(wsp, WS_FRAME_EXT2_LEN))
        {
            dbg(WS_DBG, "wait for more data.\n");
            wsp->act = PARSE_ACT_MORE_DATA;
            return rok;
        }
        ws_frame(wsp)->ext_len = htobe64(*((u64*)(ws_data(wsp))));
        wsp->data_offset += WS_FRAME_EXT2_LEN;

        dbg(WS_DBG, "message len %lld\n", ws_frame(wsp)->ext_len);

        if((ws_frame(wsp)->ext_len >> 63) == 1)
        {
            dbg(WS_ERR, "invalid extened length.\n");
            wsp->act = PARSE_ACT_ERROR;
            wsp->state = PARSE_DONE;
            return rfail;
        }
        goto _cont;
    }
    else
    {
        dbg(WS_DBG, "message len %d\n", ws_frame(wsp)->len);
        goto _cont;
    }
 _cont:
    wsp->act = PARSE_ACT_CONTINUE;
    wsp->state = PARSE_FRAME_MASK;

    return rok;
}

static s16 _parse_frame_mask_key(ws_parser_t* wsp)
{
    if(!is_data_ready(wsp, WS_FRAME_MASK_LEN))
    {
        dbg(WS_DBG, "wait for more data.\n");
        wsp->act = PARSE_ACT_MORE_DATA;
        return rok;
    }

    memcpy(ws_frame(wsp)->mask_key, ws_data(wsp), MASK_KEY_LEN);
    wsp->data_offset += WS_FRAME_MASK_LEN;

    wsp->act = PARSE_ACT_CONTINUE;
    wsp->state = PARSE_FRAME_PAYLOAD;
    return rok;
}

static void unmask_payload(ws_parser_t* wsp)
{
    s32 len = ws_frame_len(ws_frame(wsp));
    s32 i;
    s8* buf = ws_data(wsp);

    for(i = 0 ; i < len ; i++)
        ws_frame(wsp)->payload[i] = buf[i] ^ ws_frame(wsp)->mask_key[i%MASK_KEY_LEN];

    return;
}

static s16 _parse_frame_payload(ws_parser_t* wsp)
{
    s16 is_payload_ready = false;

    if(is_data_ready(wsp, ws_frame_len(ws_frame(wsp))))
    {
        dbg(WS_DBG, "all payload data is ready.\n");

        ws_frame(wsp)->payload = mem_alloc(ws_frame_len(ws_frame(wsp)));

        if(!ws_frame(wsp)->payload)
        {
            dbg(WS_DBG, "failed to alloc memory.\n");
            goto _err;
        }

        unmask_payload(wsp);

        wsp->data_offset += ws_frame_len(ws_frame(wsp));

        if(wsp->data_offset < wsp->int_buf_len)
        {
            dbg(WS_WARN, "some extra data is avail after one frame.\n");
            wsp->act = PARSE_ACT_CONTINUE;
        }
        else
        {
            dbg(WS_DBG, "no more data.\n");
            wsp->act = PARSE_ACT_OK;
        }
        /* set state for next frame */
        wsp->state = PARSE_FRAME_CTL; 
    }
    else
    {
        dbg(WS_DBG, "Wait for more data.Have:[%d], Exp:[%d].\n", data_len(wsp), ws_frame_len(ws_frame(wsp)));
        wsp->act = PARSE_ACT_MORE_DATA;
        return rok;
    }

    if(is_unfrag_frame(ws_frame(wsp)))
    {
        if(!list_empty(&(wsp->frag_frame_head)))
        {
            if(!is_ctl_frame(ws_frame(wsp)))
            {
                dbg(WS_ERR, "none-control frame received between fragment frame.\n");
                goto _err;
            }
        }
        dbg(WS_DBG, "unfrag frame received.\n");

        wsp->curr_payload_len = 0;
        is_payload_ready = true;
    }
    else
    {
        if(is_first_frag_frame(ws_frame(wsp)))
        {
            dbg(WS_DBG, "first fragmented frame.\n");

            if(!list_empty(&(wsp->frag_frame_head)))
            {
                dbg(WS_ERR, "invalid continuation fragment frame.\n");
                goto _err;
            }
            wsp->curr_payload_len = 0;
        }
        else if(is_cont_frag_frame(ws_frame(wsp)))
        {
            dbg(WS_DBG, "continue fragmented frame.\n");

            if(list_empty(&(wsp->frag_frame_head)))            
            {
                dbg(WS_ERR, "continue fragment frame recieved without first fragment.\n");
                goto _err;
            }
        }
        else
        {
            assert(is_end_frag_frame(ws_frame(wsp)));
            if(list_empty(&(wsp->frag_frame_head)))            
            {
                dbg(WS_ERR, "continue fragment frame recieved without first fragment.\n");
                goto _err;
            }
            is_payload_ready = true;
        }
    }

    buffer_frag_frame(wsp);

    if(is_payload_ready)
    {
        dbg(WS_DBG, "one frame is ready to be delivered to app layer.\n");
        
        if(queue_one_payload(wsp) != rok)
        {
            dbg(WS_ERR, "failed to queue payload.\n");
            goto _err;
        }
    }

    return rok;

 _err:
    wsp->act = PARSE_ACT_ERROR;
    wsp->act = PARSE_DONE;
    return rfail;
}

static s16 queue_one_payload(ws_parser_t* wsp)
{
    ws_frame_t *frame, *tmp;
    ws_payload_t* payload;

    assert(!list_empty(&(wsp->frag_frame_head)));
    payload = mem_alloc(sizeof(ws_payload_t));   
    if(payload == NULL)
    {
        dbg(WS_ERR, "no memory available.\n");
        return rfail;
    }

    payload->data = mem_alloc(wsp->curr_payload_len);
    if(!payload->data)
    {
        dbg(WS_ERR, "no memory available.\n");
        mem_free(payload);
        return rfail;
    }
    payload->len = 0;
    payload->op_code = 0xff;

    list_for_each_entry_safe(frame, tmp, &(wsp->frag_frame_head), frag_list)
    {
        if(payload->op_code == 0xff)
            payload->op_code = frame->op_code;

        memcpy(payload->data + payload->len ,
               frame->payload,
               ws_frame_len(frame));
        payload->len += ws_frame_len(frame);

        list_del(&(frame->frag_list));

        mem_free(frame->payload);
        mem_free(frame);
    }

    assert(payload->len == wsp->curr_payload_len);
    assert(list_empty(&(wsp->frag_frame_head)));

    list_add_tail(&(payload->payload_list), &(wsp->payload_head));

    return rok;
}

static parse_act_t ws_parse_websock(ws_parser_t* wsp, s8* data, s32 len)
{
    s16 ret;
    s16 state;

    if(agg_recv_data(wsp, data, len) != rok)
    {
        wsp->act = PARSE_ACT_ERROR;
        return wsp->act;
    }

    wsp->act = PARSE_ACT_CONTINUE;
    
    while(1)
    {
        if(wsp->act != PARSE_ACT_CONTINUE)
            break;

        assert(wsp->state < PARSE_DONE);

        state = wsp->state;
        ret = parse_func_tbl[state](wsp);

        if(ret != rok)
            dbg(WS_ERR, "failed parse at state: %d.\n", state);
    }

    return wsp->act;
}


static parse_act_t ws_parse_http(ws_parser_t* hp, s8* data, s32 len)
{
    if(agg_recv_data(hp, data, len) != rok)
    {
        hp->act = PARSE_ACT_ERROR;
        return hp->act;
    }

    hp->act = PARSE_ACT_CONTINUE;

    while(1)
    {
        if(hp->act != PARSE_ACT_CONTINUE)
            break;

        if(hp->state == PARSE_REQ_LINE)
        {
            dbg(WS_DBG, "parse http request line.\n");

            parse_request_line(hp);
        }
        else if(hp->state == PARSE_HEADERS)
        {
            dbg(WS_DBG, "parse http headers.\n");

            parse_http_headers(hp);
        }
    }
    return hp->act;
}


static s16 token_cmp(s8* begin, s8* end, s8* token)
{
    s32 len = strlen(token);

    if((end - begin) != len)
        return -1;

    return strncmp(begin, token, len);
}

static s16 token_case_cmp(s8* begin, s8* end, s8* token)
{
    s32 len = strlen(token);

    if((end - begin) != len)
        return -1;

    return strncasecmp(begin, token, len);
}

static void parse_request_line(ws_parser_t* hp)
{
    s8 *tb,*te; /* token begin, token end */
    s8 state;

#define ST_METH 0
#define ST_URI  1
#define ST_HTTP_VER 2
#define ST_LF 3

    for(tb = te = hp->buf, state = ST_METH; te < hp->buf + hp->int_buf_len ; te++)
    {
        if(*te == SP)
        {
            switch(state)
            {
            case ST_METH:
                if(token_cmp(tb, te, HTTP_METH) != 0)
                {
                    dbg(WS_ERR, "only support GET method.\n");
                    goto _out;
                }
                else
                {
                    tb = te+1;
                    state = ST_URI;
                }
                break;

            case ST_URI:
                if( te == tb || *tb != '/')
                {
                    dbg(WS_ERR, "invalid request URI.\n");
                    goto _out;
                }
                else
                {
                    tb = te+1;
                    state = ST_HTTP_VER;
                }
                break;

            default:
                dbg(WS_ERR, "invalid request URI.\n");
                goto _out;
            }
        }
        else if(*te == CR)
        {
            if(state == ST_HTTP_VER)
            {
                if(token_cmp(tb, te, HTTP_VER) != 0)
                {
                    dbg(WS_ERR, "unsupported http version.\n");
                    goto _out;
                }
                else
                {
                    tb = te+1;
                    state = ST_LF;
                }
            }
            else
            {
                dbg(WS_ERR, "invalid request line, CR in wrong place.\n");
                goto _out;
            }
        }
        else if(*te == LF)
        {
            if(state != ST_LF)
            {
                dbg(WS_ERR, "invalid request line, CR in wrong place.\n");
                goto _out;
            }
            else
            {
                hp->state = PARSE_HEADERS;
                hp->act = PARSE_ACT_CONTINUE;
                hp->data_offset = te - hp->buf + 1;
                return;
            }
        }
        else
        {
            switch(state)
            {
            case ST_METH:
            case ST_URI:
            case ST_HTTP_VER:
                break;
            default:
                goto _out;    
            }
        }
    }
    
    if(hp->int_buf_len >= MAX_REQ_LINE)
    {
        dbg(WS_ERR, "request line too long.\n");
        goto _out;
    }

    hp->act = PARSE_ACT_MORE_DATA; /* wait for more data */

    return;

 _out:
    hp->state = PARSE_DONE;
    hp->act = PARSE_ACT_ERROR;
    mem_free(hp->buf);
    hp->buf = NULL;
    hp->int_buf_len = 0;
    return;
}


const static header_t header_tbl[] = 
{
    ws_header(HDR_HOST, "Host", NULL, false),
    ws_header(HDR_UPGRADE, "Upgrade", "websocket", false),
    ws_header(HDR_CONNECTION, "Connection", "Upgrade", false),
    ws_header(HDR_SEC_WS_KEY, "Sec-WebSocket-Key", NULL, false),
    ws_header(HDR_SEC_WS_VER, "Sec-WebSocket-Version", "13", false),
    ws_header(HDR_ORIG, "Origin", NULL, true),
    ws_header(HDR_SEC_WS_PROTO, "Sec-WebSocket-Protocol", NULL, true),
    ws_header(HDR_SEC_WS_EXT, "Sec-WebSocket-Extensions", NULL, true)
};

static header_t* find_header(s8* tb, s8* te, header_t* tbl)
{
    s32 i;

    for(i = 0 ; i < HDR_MAX ; i++)
    {
        if(token_case_cmp(tb, te, (tbl+i)->name) == 0)
            return tbl+i;
    }

    return NULL;
}

static s16 store_value(s8* tb, s8* te, header_t* hd)
{
    s16 len;

    len = te - tb;

    if(!len)
    {
        dbg(WS_ERR, "value is empty.\n");
        return rfail;
    }

    hd->value.data = mem_alloc(len);

    if(hd->value.data == NULL)
    {
        dbg(WS_ERR, "failed to alloc memory.\n");
        return rfail;
    }
    memcpy(hd->value.data, tb, len);

    hd->value.len = len;

    if(hd->exp_value != NULL && strncasecmp(hd->value.data, hd->exp_value, len))
    {
        dbg(WS_DBG, "value is not expected, exp: %s.\n", hd->exp_value);
        return rok;
    }
    hd->pres = true;
    return rok;
}

static void parse_http_headers(ws_parser_t* hp)
{
    s8 *tb,*te; /* token begin, token end */
    s8 state;
    header_t* hd;
    s16 ret;

#define ST_HEAD_NAME   0
#define ST_HEAD_VALUE  1
#define ST_IN_VALUE    2
#define ST_EXP_LF      3
#define ST_END_HD_EXP_LF 4
#define ST_HD_DONE     5

    if(!hp->hdr_tbl)
    {
        hp->hdr_tbl = mem_alloc(sizeof(header_tbl));
        if(!hp->hdr_tbl)
        {
            dbg(WS_ERR, "no memory avail.\n");
            goto _out;
        }
        memcpy(hp->hdr_tbl, header_tbl, sizeof(header_tbl));
    }

    for(tb = te = hp->buf + hp->data_offset, state = ST_HEAD_NAME; te < hp->buf + hp->int_buf_len ; te++)
    {
        if(*te == COLON)
        {
            if(tb != te && state == ST_HEAD_NAME)
            {
                hd = find_header(tb, te, hp->hdr_tbl);
                if(hd == NULL)
                {
                    dbg(WS_DBG, "unknown header, ignore\n");
                }
                else
                {
                    dbg(WS_DBG, "parse header: %s\n", hd->name);
                }
                state = ST_HEAD_VALUE;
                tb = te + 1;
            }
            else if(state == ST_IN_VALUE)
            {
                continue;
            }
            else
            {
                dbg(WS_ERR, "invalid header parsing in state %d.\n", state);
                goto _out;
            }
        }
        else if(*te == SP || *te == HT)
        {
            if(state == ST_HEAD_VALUE)
            {
                tb = te + 1;
            }
            else if(state == ST_IN_VALUE)
            {
                continue;
            }
            else
            {
                dbg(WS_ERR, "invalid space or htab\n");
                goto _out;
            }
        }
        else if(*te == CR)
        {
            if(state == ST_IN_VALUE)
            {
                if(hd && hd->pres == false)
                {
                    dbg(WS_DBG, "store value for header %s.\n", hd->name);
                    ret = store_value(tb, te, hd);
                    if(ret != rok)
                    {
                        dbg(WS_DBG, "failed to store value to header: %s\n", hd->name);
                        goto _out;
                    }
                }
                tb = te+1;
                state = ST_EXP_LF;    
            }
            else if(state == ST_HEAD_NAME && tb == te)
            {
                dbg(WS_DBG, "see end of header flag.\n");
                state = ST_END_HD_EXP_LF;
            }
            else
            {
                dbg(WS_ERR, "invalid header.\n");
                goto _out;
            }
        }
        else if(*te == LF)
        {
            if(state == ST_EXP_LF)
            {
                state = ST_HEAD_NAME;
                tb = te + 1;
            }
            else if(state == ST_END_HD_EXP_LF)
            {
                dbg(WS_DBG, "header parse done.\n");
                state = ST_HD_DONE;
                break;
            }
            else
            {
                dbg(WS_ERR, "invalid header.\n");
                goto _out;
            }
        }
        else
        {
            switch(state)
            {
            case ST_HEAD_VALUE:
                state = ST_IN_VALUE;
                break;
            case ST_HEAD_NAME:
            case ST_IN_VALUE:
                break;
            default:
                goto _out;
            }
        }
    }
    
    if(state == ST_HD_DONE)
    {
        hp->state = PARSE_DONE;
        hp->act = PARSE_ACT_OK;
        mem_free(hp->buf);
        hp->buf = NULL;
        hp->int_buf_len = 0;
    }
    else if( hp->int_buf_len > MAX_HTTP_LEN )
    {
        dbg(WS_ERR, "http messsage is too big.\n");
        goto _out;
    }
    else
        hp->act = PARSE_ACT_MORE_DATA; /* wait for more data */

    return;

 _out:
    hp->state = PARSE_DONE;
    hp->act = PARSE_ACT_ERROR;
    if(hp->buf)
        mem_free(hp->buf);
    hp->buf = NULL;
    hp->int_buf_len = 0;
    if(hp->hdr_tbl)
        free_hdr_tbl(hp->hdr_tbl);
    hp->hdr_tbl = NULL;
    return;
}

