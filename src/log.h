#ifndef _SS_WS_LOG_H_
#define _SS_WS_LOG_H_

#include "gen.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/time.h>


extern u8 sys_dbg_level; 

enum dbg_level 
{
    WS_DBG = 0,
    WS_INFO,
    WS_WARN,
    WS_ERR,
};

#define dbg(level, fmt, args...)                                    \
    do {                                                            \
        if(level >= sys_dbg_level)                                  \
        {                                                           \
            do_log(__FILE__,__LINE__,__FUNCTION__, fmt, ##args);    \
        }                                                           \
    } while(0)

#define  MAX_LOG_MSG_SIZE 1024

typedef enum logger_type
{
    FILE_LOGGER = 0,
    LOGGER_TYPE_MAX,
} logger_type_t;


typedef struct logger 
{
    s16 (*init)(struct logger* p, void* cfg);
    void (*deinit)(struct logger* p);
    void (*log)(struct logger* logger, const s8* msg, u32 len);
    void (*flush)(struct logger* logger);
    void* data;
} logger_t;


///////////// File logger implementation ///////////
#define _LOG_BUF_SIZE 8192
#define is_log_buf_avail(lb, len)\
    (((_LOG_BUF_SIZE - lb->wptr + lb->rptr - 1) % _LOG_BUF_SIZE) >= len)
#define is_log_buf_empty(lb) \
    (lb->wptr == lb->rptr)

typedef struct file_log_cfg
{
    s8* fname;
    u32 sz_limit;
    u32 file_inst_limit;
} file_log_cfg_t;

typedef struct log_buf
{
    pthread_mutex_t lock;
    u32 rptr;
    u32 wptr;
    s8 data[_LOG_BUF_SIZE];
} log_buf_t;

typedef struct file_logger
{
    /* first must be logger_t */
    logger_t logger;            
    /* config */
    file_log_cfg_t cfg;
    /* logging & thread related */
    log_buf_t* log_buf;
    pthread_t tid;
    s32 pipefd[2];
    /* log file management */
    u32 log_file_inst;
    u32 log_file_flag;
    s8 log_fname[32];
    s32 fd;
} file_logger_t;

s16 log_init(logger_type_t type, void* cfg);
void log_deinit();
void do_log(const s8* file, s32 line, const s8* func, s8* fmt, ...);
void flush_log();

#endif
