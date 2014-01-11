#ifndef _SS_WS_PARSE_H
#define _SS_WS_PARSE_H

#include "gen.h"

#define MAX_REQ_LINE 512
#define MAX_HTTP_LEN 2048
#define MAX_HTTP_RSP 512

#define SP ' '
#define HT '\t'
#define CR '\r'
#define LF '\n'
#define COLON ':'
#define HTTP_VER "HTTP/1.1"
#define HTTP_METH "GET"

#define HTTP_101 "Switching Protocols"
#define HTTP_400 "Bad Request"
#define HTTP_500 "Internal Server Error"


#define WS_FRAME_CTL_LEN   2
#define WS_FRAME_EXT1_LEN  2
#define WS_FRAME_EXT2_LEN  8
#define WS_FRAME_MASK_LEN  4

#define WS_OP_CODE_CONT 0
#define WS_OP_CODE_TEXT 1
#define WS_OP_CODE_BIN  2
#define WS_OP_CODE_CLOSE 8
#define WS_OP_CODE_PING  9
#define WS_OP_CODE_PONE  0xa



typedef enum
{
    TYPE_HTTP,
    TYPE_WEBSOCK,
    TYPE_INVALID,
} parser_type_t;

typedef struct 
{
    u32 code;
    s8* phrase;
} http_rphrase_t;


#define PARSE_REQ_LINE  0              
#define PARSE_HEADERS   1              

#define PARSE_FRAME_CTL   0
#define PARSE_FRAME_LEN   1
#define PARSE_FRAME_MASK  2
#define PARSE_FRAME_PAYLOAD 3

#define PARSE_DONE PARSE_FRAME_PAYLOAD+1                      


typedef enum
{
    PARSE_ACT_CONTINUE,
    PARSE_ACT_OK,
    PARSE_ACT_MORE_DATA,
    PARSE_ACT_ERROR,
    PARSE_ACT_MAX,
} parse_act_t;


typedef struct header
{
    s8 pres;
    s32 id;
    s8* name;
    str_t value;
    s8* exp_value;
    s8 is_opt;
} header_t;


#define HDR_HOST          0
#define HDR_UPGRADE       1
#define HDR_CONNECTION    2
#define HDR_SEC_WS_KEY    3
#define HDR_SEC_WS_VER    4
#define HDR_ORIG          5
#define HDR_SEC_WS_PROTO  6
#define HDR_SEC_WS_EXT    7
#define HDR_MAX           HDR_SEC_WS_EXT+1

#define ws_header(hdr, hdr_name, val, opt)                               \
    {.pres=false, .id=hdr, .name=hdr_name, .value={.data=NULL, .len=0}, .exp_value=val, .is_opt=opt}


#define ws_hdr_val(sess, hdr)                   \
    sess->p_ctl->parser.hdr_tbl[hdr].value.data
#define ws_hdr_len(sess, hdr)                   \
    sess->p_ctl->parser.hdr_tbl[hdr].value.len

#define is_data_ready(parser, exp_len)          \
    (((parser->int_buf_len - parser->data_offset) >= exp_len)? true:false)

#define data_len(parser)                        \
    (parser->int_buf_len - parser->data_offset)

#define ws_data(parser)                         \
    (parser->buf + parser->data_offset)
#define ws_frame(parser)                        \
    (parser->frame)

#define is_ctl_frame(frame)                    \
    (frame->op_code > WS_OP_CODE_BIN)

#define is_unfrag_frame(frame)                    \
    (frame->op_code != 0 && frame->fin == 1)

#define is_first_frag_frame(frame)              \
    (frame->fin == 0 && frame->op_code != 0)

#define is_cont_frag_frame(frame)               \
    (frame->fin == 0 && frame->op_code == 0)

#define is_end_frag_frame(frame)                \
    (frame->fin == 1 && frame->op_code == 0)

#define ws_frame_len(frame)                     \
    ((frame->len > 125)?frame->ext_len:frame->len)

#define buffer_frag_frame(parser)                                       \
    do                                                                  \
    {                                                                   \
        list_add_tail(&(ws_frame(parser)->frag_list), &(parser->frag_frame_head)); \
        parser->curr_payload_len += ws_frame_len(ws_frame(parser));     \
        ws_frame(parser) = NULL;                                        \
    }                                                                   \
    while(0)

#define MASK_KEY_LEN 4
typedef struct ws_frame
{
    u32 fin:1;
    u32 rsv:3;
    u32 op_code:4;
    u32 mask:1;
    u32 len:7;

    u64 ext_len;
    s8  mask_key[MASK_KEY_LEN];
    s8* payload;

    list_head_t frag_list;
} ws_frame_t;

typedef struct ws_payload
{
    list_head_t payload_list;
    u32 op_code;
    s8* data;
    s32 len;
} ws_payload_t;

typedef struct ws_parser
{
    s32 state;
    parse_act_t act;
    s8* buf;
    s32 int_buf_len;
    s32 data_offset;

    header_t* hdr_tbl;
    ws_frame_t* frame;

    s32 curr_payload_len;

    list_head_t frag_frame_head;
    list_head_t payload_head;

} ws_parser_t;

typedef struct ws_parse_ctl
{
    parser_type_t type;
    ws_parser_t parser;
} ws_parse_ctl_t;


typedef s16 (*_frame_parse_func_t)(ws_parser_t* p);

ws_parse_ctl_t* alloc_parse_ctl();
void free_parse_ctl(ws_parse_ctl_t* pctl);
s8* get_rphrase(u32 code);
parse_act_t ws_parse(ws_parse_ctl_t* p_ctl, s8* data, s32 len);
s16 ws_build_frame(ws_frame_t* frame, s8** buf, s32* len);

#endif
