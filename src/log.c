#include "log.h"

u8 sys_dbg_level = WS_WARN;

static logger_t* log_inst = NULL;

/////////////// websockt file logger implementation ////////////////
// thread-safe logging with one extra logging thread //////////////

static s32 file_log_open(file_logger_t*);
static s32 file_log_write(s32 fd, s8* buf, s32 len);
static void check_rotate(file_logger_t*);
static s16 file_log_init(logger_t* logger, void* cfg);
static logger_t* get_logger(logger_type_t type);
static s16 file_log_init(logger_t* logger, void* cfg);
static void* file_log_thread(void* argv);
static void file_do_log(logger_t* logger, const s8 *data, u32 len);
static void file_log_deinit(logger_t* logger);
static void file_log_flush(logger_t* logger);

static file_logger_t file_logger =
{
    .logger = {
        .init = file_log_init,
        .deinit = file_log_deinit,
        .log = file_do_log,
        .flush = file_log_flush,
    },
};


static s32 file_log_open(file_logger_t* logp)
{
    logp->fd = open(logp->log_fname, logp->log_file_flag, S_IRWXU|S_IRGRP|S_IROTH);

    if(logp->fd < 0)
        return rfail;

    return rok;
}

static s32 file_log_write(s32 fd, s8* buf, s32 len)
{
    s32 tmp, cnt = 0;

    while(cnt < len)
    {
        tmp = write(fd, buf, len);
        if(tmp > 0)
            cnt += tmp;
    }

    return cnt;
}

static void check_rotate(file_logger_t* logp)
{
    s16 ret = rok;
    struct stat state;
    s32 i;
    s8 old[32], new[32];

    ret = fstat(logp->fd, &state);
    assert(ret == rok);

    /* time to rotate */
    if(state.st_size >= logp->cfg.sz_limit)
    {
        close(logp->fd);
        
        for(i = logp->log_file_inst ; i > 0 ; i--)
        {
            sprintf(new, "%s.%d", logp->log_fname, i);
            if(i == 1)
                strcpy(old, logp->log_fname);
            else
                sprintf(old, "%s.%d", logp->log_fname, i-1);

            rename(old, new);
        }

        if(logp->log_file_inst < logp->cfg.file_inst_limit-1)
            logp->log_file_inst++;

        ret = file_log_open(logp);

        assert(ret == rok);
    }
    return;
}

static s16 file_log_init(logger_t* logger, void* cfg)
{
    s16 ret = rok;

    file_logger_t* logp = (file_logger_t*)logger;

    if(cfg != NULL)
        memcpy(&(logp->cfg), cfg, sizeof(file_log_cfg_t));        
    else
    {
        logp->cfg.fname="ws_log";
        logp->cfg.sz_limit=1024*1024;
        logp->cfg.file_inst_limit=5;
    }

    logp->log_file_inst = 1;
    sprintf(logp->log_fname, "%s.out", logp->cfg.fname);

    logp->log_file_flag = O_WRONLY|O_APPEND|O_CREAT;
    ret = file_log_open(logp);
    if(ret != rok)
        goto _out;

    /* alloc all the buffer for logging */
    logp->log_buf = (log_buf_t*)calloc(1, sizeof(log_buf_t));
    if(!logp->log_buf)
        goto _out;

    ret = pthread_mutex_init(&(logp->log_buf->lock), NULL);
    if(ret != rok)
        goto _out;

    ret = pipe(logp->pipefd);
    fcntl(logp->pipefd[0], F_SETFL, O_NONBLOCK);
    fcntl(logp->pipefd[1], F_SETFL, O_NONBLOCK);

    if(ret != rok)
        goto _out;

    ret = pthread_create(&(logp->tid), NULL, file_log_thread, (void*)logp);
    if(ret != rok)
        goto _out;

    return rok;

 _out:
    if(logp->log_buf) free(logp->log_buf);
    if(logp->fd > 0 ) close(logp->fd);
    if(logp->pipefd[0] > 0) 
    {
        close(logp->pipefd[0]);
        close(logp->pipefd[1]);
    }
    return rfail;
}


static void* file_log_thread(void* argv)
{
    file_logger_t* logp = (file_logger_t*)argv;
    log_buf_t* lb = logp->log_buf;

    s16 ret;
    s8 c;
    u32 wptr, rptr;
    fd_set rfds;
    struct timeval tv;

    while(1)
    {
        c = 'x';
        FD_ZERO(&rfds);
        FD_SET(logp->pipefd[0], &rfds);

        tv.tv_sec = 1;          /* 1 seconds logging delay */
        tv.tv_usec = 0;

        ret = select(logp->pipefd[0]+1, &rfds, NULL, NULL, &tv);
        if(ret == -1)
        {
            if(errno == EINTR)
                continue;
            else
            {
                sleep(1);       /* what's going on? */
                continue;
            }
        }
        else if( ret > 0) /* wake up to do work */
        {
            if(FD_ISSET(logp->pipefd[0], &rfds))
            {
                read(logp->pipefd[0], &c, 1);
                if(c == 'k')    /* we are killed */
                    break;
            }
            else
                assert(false);
        }
        else /* wakeup by time */
        {
            check_rotate(logp);
        }

        /* snapshot the buffer */
        pthread_mutex_lock(&(lb->lock));

        if(is_log_buf_empty(lb))
        {
            pthread_mutex_unlock(&(lb->lock));
            continue;
        }
        wptr = lb->wptr;
        rptr = lb->rptr;

        pthread_mutex_unlock(&(lb->lock));

        int cnt = 0;
        if(rptr < wptr)
        {
            cnt = file_log_write(logp->fd, lb->data + rptr, wptr-rptr);
        }
        else
        {
            cnt += file_log_write(logp->fd, lb->data + rptr, _LOG_BUF_SIZE - rptr);
            cnt += file_log_write(logp->fd, lb->data, wptr);
        }
        /* barrier here? */
        lb->rptr = (lb->rptr + cnt) % _LOG_BUF_SIZE;
    }

    return NULL;
}

static void file_do_log(logger_t* logger, const s8 *data, u32 len)
{
    file_logger_t* logp = (file_logger_t*)logger;
    log_buf_t *lb = logp->log_buf;
    s16 lb_full = false;
    s16 retry = 0;
    u32 i;

 again:
    pthread_mutex_lock(&(lb->lock));
    if(is_log_buf_avail(lb, len))
    {
        for(i = 0 ; i < len ; i++)
        {
            *(logp->log_buf->data + lb->wptr) = *(data+i);
            lb->wptr = (lb->wptr+1) % _LOG_BUF_SIZE;
        }
    }
    else
    {
        lb_full = true;
    }
    pthread_mutex_unlock(&(lb->lock));

    if(lb_full && retry <3) /* wake up and try again */
    {
        retry++;
        write(logp->pipefd[1], "1", 1);
        goto again;
    }
    return;
}


static void file_log_flush(logger_t* logger)
{
    file_logger_t* logp = (file_logger_t*)logger;
    write(logp->pipefd[1], "1", 1);
}


static void file_log_deinit(logger_t* logger)
{
    file_logger_t* logp = (file_logger_t*)logger;

    file_log_flush(logger);

    /* wake up and close logging thread */
    write(logp->pipefd[1], "k", 1);
    pthread_join(logp->tid, NULL);

    free(logp->log_buf);

    close(logp->pipefd[0]);
    close(logp->pipefd[1]);

    close(logp->fd);
}


//////////////// Logger interface //////////////////////

static logger_t* get_logger(logger_type_t type)
{
    switch(type)
    {
    case FILE_LOGGER:
    default:
        return (logger_t*)&file_logger;
    }
}

s16 log_init(logger_type_t type, void* cfg)
{
    s16 ret = rok;

    log_inst = get_logger(type);
    if(log_inst == NULL)
        return rfail;

    ret = log_inst->init(log_inst, cfg);
  
    return ret;
}

void log_deinit()
{
    if(log_inst)
        log_inst->deinit(log_inst);
    return ;
}

void do_log(const s8* file, s32 line, const s8* func, s8* fmt, ...)
{
    s8 buf[MAX_LOG_MSG_SIZE];
    s8* ptr = buf;
    va_list list;
    u32 len = 0;
    struct tm         localtime;
    struct timeval    timenow;

    if(!log_inst)
        return;

    gettimeofday(&timenow, NULL);

    localtime_r(&timenow.tv_sec, &localtime);
    
    len += strftime(ptr, MAX_LOG_MSG_SIZE, "%m-%d %H:%M:%S", &localtime);
    ptr = buf + len;
    
    len += snprintf(ptr, MAX_LOG_MSG_SIZE - len ,".%03d: ", (s32)timenow.tv_usec/1000);
    ptr = buf + len;
    
    len += snprintf(ptr, MAX_LOG_MSG_SIZE - len, "%s:%d %s: ", file, line, func);
    ptr = buf + len;

    va_start(list, fmt);
    len += vsnprintf(ptr,  MAX_LOG_MSG_SIZE - len, fmt, list);
    va_end(list);

    log_inst->log(log_inst, buf, len);
}

void flush_log()
{
    if(!log_inst)
        return;

    log_inst->flush(log_inst);
}
