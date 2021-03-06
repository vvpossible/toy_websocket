#include "sock.h"
#include "mem.h"
#include "log.h"
#include "gen.h"

int main(int argc, char** argv)
{
    s16 ret = rok;

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

    ret = sock_init(SOCK_TYPE_TCP, argv[1], atoi(argv[2]));
    if(ret != rok)
    {
        dbg(WS_ERR, "failed to init socket.\n");
        goto _err1;
    }

    //sock_reg_callback(websocket callbacks);

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
