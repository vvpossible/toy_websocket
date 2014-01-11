#include "sock.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>


static sock_cp_t socket_cp;
static sock_cp_t* sk_cp = &socket_cp;

#define  _sock_callback(func, args...)                  \
    ({                                                  \
        s16 tmp = rok;                                  \
        if(sk_cp && sk_cp->ops && sk_cp->cb_ops->func)  \
            tmp = sk_cp->cb_ops->func(args);            \
        tmp;                                            \
    }) 

/* static function declarations */
static s16 tcp_server_stop();
static void server_spin();
static s16 tcp_server_start();
static s16 tcp_sk_send(sock_cb_t* sk_cb, s8* data, s32);
static s16 tcp_sk_recv(sock_cb_t* sk_cb, s8* data, s32 *len);
static s16 tcp_get_stats(sock_cb_t* sk_cb, s8 flag, sock_stats_t* out);
static s16 tcp_reset_stats(sock_cb_t* sk_cb, s8 flag);
static s16 tcp_sk_close(sock_cb_t* sk_cb, s8 flag);
static sock_cb_t* alloc_sock_cb(s32 connfd, struct sockaddr_in* peer_addr);
static void free_sock_cb(sock_cb_t* sk_cb);
static s16 tcp_sock_proc_event(struct epoll_event* ev, sock_action_t* action);

////////////////////////////////////////
/* default upper implementation   */
////////////////////////////////////////
static s16 default_on_bind(s32 fd);
static s16 default_on_listen(s32 fd);
static s16 default_on_create(sock_cb_t* sk_cb, sock_action_t* act);
static s16 default_on_recv(void* sk_cb, s8* data, s32 len, sock_action_t* act);
static s16 default_on_close(void* sk_cb);
static s16 default_on_error(void* sk_cb, sock_action_t* act);

static s16 default_on_bind(s32 fd)
{
    dbg(WS_DBG, "socket %d bind.\n", fd);
    return rok;
}

static s16 default_on_listen(s32 fd)
{
    dbg(WS_DBG, "socket %d listen.\n", fd);
    return rok;
}

static s16 default_on_create(sock_cb_t* sk_cb, sock_action_t* act)
{
    dbg(WS_DBG, "receive new connection from %s:%d\n", sk_cb->src_addr, sk_cb->src_port);

    sk_cb->priv = sk_cb;

    *act = SOCK_ACT_NO;

    return rok;
}

static s16 default_on_recv(void* priv, s8* data, s32 len, sock_action_t* act)
{
    sock_cb_t* sk_cb = (sock_cb_t*)priv;

    dbg(WS_DBG, "receive something from %s:%d\n", sk_cb->src_addr, sk_cb->src_port);

    s8 buf[256];
    snprintf(buf, sizeof(buf), "%s", (s8*)data);
    dbg(WS_DBG, "data: %s", buf);

    *act = SOCK_ACT_NO;

    return rok;
}

static s16 default_on_close(void* priv)
{
    sock_cb_t* sk_cb = (sock_cb_t*)priv;

    dbg(WS_DBG, "connection from %s:%d is closed.\n", sk_cb->src_addr, sk_cb->src_port);

    return rok;
}

static s16 default_on_error(void* priv, sock_action_t* act)
{
    sock_cb_t* sk_cb = (sock_cb_t*)priv;

    dbg(WS_ERR, "socket %s:%d has error.\n", sk_cb->src_addr, sk_cb->src_port);

    *act = SOCK_ACT_CLOSE;

    return rok;
}

static sock_cb_ops_t default_callbacks = 
{
    .on_bind = default_on_bind,
    .on_listen = default_on_listen,
    .on_create = default_on_create,
    .on_recv = default_on_recv,
    .on_close = default_on_close,
    .on_error = default_on_error,
};

/////////////////////////////////////////

/////////////TCP service access point/////////////////
static s16 tcp_sk_send(sock_cb_t* sk_cb, s8* data, s32 dlen)
{
    s32 ret;
    cong_block_t *cb, *tmp;

    list_for_each_entry_safe(cb, tmp, &(sk_cb->cong_q_head), cong_list)
    {
        dbg(WS_WARN, "retransmit congestion data first.\n");
        ret = send(sk_cb->sock_fd, cb->buf, cb->len, 0);
        if(ret < 0)          /* give up */
            return rfail;

        dbg(WS_WARN, "succeed to send congestion block.\n");
        list_del(&(cb->cong_list));
        mem_free(cb->buf);
        cb->buf = NULL;
        mem_free(cb);
        cb = NULL;
    }

    ret = send(sk_cb->sock_fd, data, dlen, 0);

    if(ret < 0)
    {
        dbg(WS_ERR, "unable to send.\n");

        if(errno != EAGAIN && errno != EWOULDBLOCK)
        {
            dbg(WS_ERR, "failed to send, notify upper layer.\n");
            return rfail;
        }
        
        dbg(WS_WARN, "congestion happened, cache the buffer.\n");

        cong_block_t* block = mem_alloc(sizeof(cong_block_t));
        if(!block)
            return rfail;

        bzero(block, sizeof(cong_block_t));
        block->buf = mem_alloc(dlen);
        if(!block->buf)
        {
            mem_free(block);
            return rfail;
        }
        memcpy(block->buf, data, dlen);
        block->len = dlen;

        dbg(WS_WARN, "cache the unsent buffer in queue.\n");
        list_add_tail(&(block->cong_list), &(sk_cb->cong_q_head));
    }

    return rok;
}

static s16 tcp_sk_recv(sock_cb_t* sk_cb, s8* data, s32* len)
{
    return rok;
}

static s16 tcp_get_stats(sock_cb_t* sk_cb, s8 flag, sock_stats_t* out)
{
    memcpy(out, &(sk_cb->stats), sizeof(sock_stats_t));
    return rok;
}

static s16 tcp_reset_stats(sock_cb_t* sk_cb, s8 flag)
{
    memset(&(sk_cb->stats), 0, sizeof(sock_stats_t));
    return rok;
}

static s16 tcp_sk_close(sock_cb_t* sk_cb, s8 flag)
{
    free_sock_cb(sk_cb);
    return rok;
}

static sock_ops_t tcp_ops =
{
    .send = tcp_sk_send,
    .recv = tcp_sk_recv,
    .stats = tcp_get_stats,
    .reset_stats = tcp_reset_stats,
    .close = tcp_sk_close
};

static s16 tcp_server_start()
{
    struct sockaddr_in serv_addr;
    s16 ret;

    if(!sk_cp->init)
    {
        dbg(WS_ERR, "socket layer is not initialized.\n");
        return rfail;
    }

    s32 fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0)
    {
        dbg(WS_ERR, "failed to create socket, errno = %d\n", errno);
        return rfail;
    }
    sk_cp->data = fd;

    s32 option = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    bzero(&serv_addr, 0);
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_port=htons(sk_cp->port);
    ret = inet_aton(sk_cp->host, &serv_addr.sin_addr);
    if(ret < 0)
    {
        dbg(WS_ERR, "Host name is invalid %s.\n", sk_cp->host);
        return rfail;
    }

    ret = bind(fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr));
    if(ret < 0)
    {
        dbg(WS_ERR, "failed to bind to %s. errno=%d\n", sk_cp->host, errno);

        return rfail;
    }

    ret = _sock_callback(on_bind, fd);

    ret = listen(fd, 5);
    if(ret < 0)
    {
        dbg(WS_ERR, "failed to listen on %s port %d. errno=%d\n", sk_cp->host, sk_cp->port, errno);
        return rfail;
    }

    ret = _sock_callback(on_listen, fd);

    dbg(WS_DBG, "server main loop starts ...\n");
 
    server_spin();

    return rok;
}

static sock_cb_t* alloc_sock_cb(s32 connfd, struct sockaddr_in* peer_addr)
{
    sock_cb_t* sk_cb = mem_alloc(sizeof(sock_cb_t));
    if(!sk_cb)
    {
        dbg(WS_ERR, "memory allocation failed for socket cb.\n");
        return NULL;
    }

    memset(sk_cb, 0, sizeof(sock_cb_t));

    sk_cb->sock_fd = connfd;

    strcpy(sk_cb->src_addr, inet_ntoa(peer_addr->sin_addr));
    sk_cb->src_port = ntohs(peer_addr->sin_port);

    INIT_LIST_HEAD(&(sk_cb->cong_q_head));

    sk_cp->num_conns++;
    list_add_tail(&(sk_cb->sk_cb_list), &(sk_cp->sk_cb_head));

    sk_cb->ops = sk_cp->ops;

    return sk_cb;
}

static void free_sock_cb(sock_cb_t* sk_cb)
{
    struct epoll_event ev;

    epoll_ctl(sk_cp->epoll_fd, EPOLL_CTL_DEL, sk_cb->sock_fd, &ev);

    close(sk_cb->sock_fd);

    _sock_callback(on_close, sk_cb->priv);

    sk_cp->num_conns--;

    assert(sk_cp->num_conns >= 0);    

    list_del(&(sk_cb->sk_cb_list));

    cong_block_t *cb, *tmp;
    list_for_each_entry_safe(cb, tmp, &(sk_cb->cong_q_head), cong_list)
    {
        dbg(WS_WARN, "remove congestion data.\n");

        list_del(&(cb->cong_list));
        mem_free(cb->buf);
        cb->buf = NULL;
        mem_free(cb);
        cb = NULL;
    }

    mem_free(sk_cb);
}

static void server_spin()
{
    s32 nfds, n, connfd, epollfd;
    s32 listen_fd = sk_cp->data;
    struct sockaddr_in peer_addr;
    socklen_t addrlen = sizeof(peer_addr);
    s16 ret = rok;
    sock_action_t action;

#define MAX_EVENTS 32
    struct epoll_event ev, events[MAX_EVENTS];

    epollfd = epoll_create(1);
    if (epollfd == -1) {
        dbg(WS_ERR, "epoll_create failed with erron: %d\n", errno);
        return;
    }

    sk_cp->epoll_fd = epollfd;

    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_fd, &ev) == -1)
    {
        dbg(WS_ERR, "epoll_ctl: failed to add listen fd. errno: %d\n", errno);
        return;
    }

    while(!sk_cp->stop)
    {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if(errno == EINTR)
                continue;
            else
            {
                dbg(WS_ERR, "epoll_wait failed. errno: %d\n", errno);
                assert(false);
            }
        }
        for (n = 0; n < nfds; ++n) {

            if (events[n].data.fd == listen_fd) 
            {
                connfd = accept(listen_fd,
                     (struct sockaddr *)&peer_addr, &addrlen);

                if (connfd == -1) {
                    dbg(WS_ERR, "failed to accept new socket. errno: %d\n", errno);
                    continue;
                }

                sock_cb_t* sk_cb = alloc_sock_cb(connfd, &peer_addr);
                if(sk_cb == NULL)
                {
                    dbg(WS_ERR, "Failed to alloc socket cb for new conn %d from %s\n.", connfd, inet_ntoa(peer_addr.sin_addr));
                    continue;
                }
                /* do on create callback */
                action = SOCK_ACT_NO;
                _sock_callback(on_create, sk_cb, &action);

                if(action == SOCK_ACT_CLOSE)
                {
                    dbg(WS_WARN, "upper layer reject the connection.\n");
                    free_sock_cb(sk_cb);
                    continue;
                }

                fcntl(sk_cb->sock_fd, F_SETFL, O_NONBLOCK);                  
                ev.events = EPOLLIN | EPOLLERR ;
                ev.data.ptr = sk_cb;

                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sk_cb->sock_fd,
                   &ev) == -1) 
                {
                    dbg(WS_ERR, "failed to call epoll_ctl, free sock_cb %p.\n", sk_cb);
                    free_sock_cb(sk_cb);                    
                    continue;
                }
            }
            else 
            {
                ret = tcp_sock_proc_event(&events[n], &action);
                if(ret != rok)
                    dbg(WS_ERR, "failed to process events.\n");

                switch(action)
                {
                case SOCK_ACT_CLOSE:
                    dbg(WS_INFO, "Take action: close this socket.\n");
                    free_sock_cb(((sock_cb_t*)events[n].data.ptr));

                default:
                    continue;
                }
            }
        }
    }
    /* todo: cleanup */
    dbg(WS_DBG, "todo: cleanup needed.\n");
}

static s16 tcp_server_stop()
{
    dbg(WS_DBG, "todo: release each socket control block.\n");    

    sk_cp->stop = true;

    return rok;
}

static s16 tcp_sock_proc_event(struct epoll_event* ev, sock_action_t* action)
{
    sock_cb_t* sk_cb = (sock_cb_t*)(ev->data).ptr;
    s32 count, value; 
    s16 ret = rok;
    s8 buf[1024];
    s8* dptr = buf;
    s32 len = sizeof(buf);

    if(ev->events | EPOLLIN)
    {
        ret = ioctl(sk_cb->sock_fd, SIOCINQ, &value);
        if(ret < 0 || value == 0)
        {
            dbg(WS_ERR, "failed to prefetch readable count, use default %d.\n", len);
        }
        else
        {
            dbg(WS_DBG, "%d bytes available.\n", value);
            len = value;
            dptr = (s8*)mem_alloc(value);
            assert(dptr);
        }

        bzero(dptr, len);        
        count = recv(sk_cb->sock_fd, dptr, len, 0);

        if(count == -1)
        {
            if(errno == EINTR)
            {
                dbg(WS_ERR, "read from socket was interrupted.\n");
            }
            else
            {
                dbg(WS_ERR, "error happened for reading, close socket.\n");
                *action = SOCK_ACT_CLOSE;
            }
            goto _out;
        }
        else if(count == 0)
        {
            dbg(WS_DBG, "peer close the socket.\n");
            *action = SOCK_ACT_CLOSE;
            goto _out;
        }

        dbg(WS_DBG, "%d bytes received.\n", count);

        *action = SOCK_ACT_NO;
        ret = _sock_callback(on_recv, sk_cb->priv, dptr, count, action);

    _out:
        if(dptr != buf)
            mem_free(dptr);

        return ret;
    }
    else if(ev->events | EPOLLERR)
    {
        *action = SOCK_ACT_NO;
        ret =  _sock_callback(on_error, sk_cb->priv, action);
    }
    else if(ev->events | EPOLLOUT)
    {
        dbg(WS_INFO, "socket become writable.\n");
    }

    return ret;
}

//////////////////////////////////////////////////


//////////////// public interfaces ///////////////

s16 sock_init(sock_type_t type, s8* host, s16 port)
{
    sk_cp->type = type;
    strcpy(sk_cp->host, host);
    sk_cp->port = port;
    INIT_LIST_HEAD(&(sk_cp->sk_cb_head));
    sk_cp->stop = false;

    switch(sk_cp->type)
    {
    case SOCK_TYPE_TCP:
        sk_cp->cb_ops = &default_callbacks;
        sk_cp->ops = &tcp_ops;
        sk_cp->sock_start = tcp_server_start;
        sk_cp->sock_stop = tcp_server_stop;
        break;
    /* currently only support TCP */
    case SOCK_TYPE_UDP:
    case SOCK_TYPE_SCTP:
    default:
        return rfail;
        break;
    }

    sk_cp->init = true;

    return rok;
}

s16 sock_reg_callback(sock_cb_ops_t* ops)
{
    if(!sk_cp->init)
    {
        dbg(WS_ERR, "socket layer is not init yet.\n");
        return rfail;
    }

    assert(ops);

    sk_cp->cb_ops = ops;

    return rok;
}

s16 sock_server_start()
{
    if(!sk_cp->init)
    {
        dbg(WS_ERR, "socket layer is not init yet.\n");
        return rfail;
    }

    return (*(sk_cp->sock_start))();
}

s16 sock_server_stop()
{
    if(!sk_cp->init)
    {
        dbg(WS_ERR, "socket layer is not init yet.\n");
        return rfail;
    }

    (*(sk_cp->sock_stop))();

    return rok;
}
