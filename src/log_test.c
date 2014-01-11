#include "log.h"
#include "pthread.h"


void* thread1(void* argv)
{
    u32 i = 0 ;

    while(i < 10000)
    {
        dbg(WS_ERR, "[SEQ %d]: hello from %s\n", i++, "thread1");
        usleep(500000);
    }
    return NULL;
}

void* thread2(void* argv)
{
    u32 i = 0 ;

    while(i < 10000)
    {
        dbg(WS_ERR, "[SEQ %d]: hello from %s\n", i++, "thread2");
        usleep(200000);
    }
    return NULL;
}


int main(int arg, char** argv)
{
    s16 ret;
    pthread_t tid1, tid2;

    file_log_cfg_t cfg;
    cfg.sz_limit = 10240;
    cfg.fname = "ws_log_test";
    cfg.file_inst_limit = 3;

    ret = log_init(FILE_LOGGER, &cfg);
    if(ret != rok)
        return -1;


    pthread_create(&tid1, NULL, thread1, (void*)NULL);
    pthread_create(&tid2, NULL, thread2, (void*)NULL);

    s32 i = 0;
    while(i<100)
    {
        dbg(WS_DBG, "seq [%d] hello from %s\n", i++, "main thread");
        usleep(100000);
    }

    log_deinit();

    return 0;
}
