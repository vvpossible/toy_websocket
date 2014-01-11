#include<stdio.h>
#include "mem.h"
#include <mcheck.h>
#include "log.h"


int main(int argc, char** argv)
{
    s16 ret = rok;
    s16 i,j;
    s16 test_array[] = {16, 32, 63, 65, 127, 255, 400, 512, 1024};

    mtrace();

    ret = mem_init();

    if(ret != rok)
        goto _err;

    file_log_cfg_t cfg;
    cfg.fname = "ws_mem";
    cfg.sz_limit = 64*1024;     /* 64k */
    cfg.file_inst_limit = 5;

    ret = log_init(0, &cfg);

    char* buf[300];

    for(j = 0 ; j < arr_size(test_array) ; j++)
    {
        for(i = 0 ; i < arr_size(buf); i++)    
        {
            buf[i] = mem_alloc(test_array[j]);
            if(buf[i] == NULL)
                goto _err;

            memset(buf[i], 0, sizeof(test_array[j]));
        }
        for(i = 0 ; i < arr_size(buf); i++)
        {
            mem_free(buf[i]);
        }
    

        for(i = 0 ; i < arr_size(buf); i++)
        {
            buf[i] = mem_alloc(test_array[j]);
            if(buf[i] == NULL)
                goto _err;

            mem_free(buf[i]);
        }

        int k;
        for(i = 0 ; i < arr_size(buf); i++)
        {
            buf[i] = mem_alloc(test_array[j]);
            if(buf[i] == NULL)
                goto _err;


            if(i> 0 && (i % 15 == 0))
            {
                for(k = 1 ; k <= 15 ; k++) 
                    mem_free(buf[i-k]);
            }
        }
        for(k = 1 ; k <= 15 ; k++) 
            mem_free(buf[i-k]);


    }
    mem_deinit();

    muntrace();

    return 0;

 _err:
    return -1;
}
