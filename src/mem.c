#include "mem.h"
#include "log.h"

#ifdef USE_MEM_POOL

static mem_pool_t mem_pool;

static s16 subpool_init(s16);

static cache_t* alloc_cache(sub_pool_t*);

static void subpool_deinit(s16);

static void* alloc_blk(cache_t*);

static const mem_pool_cfg_t mem_cfg[] = 
{
    {32, 1},
    {64, 1},
    {128, 1},
    {256, 4},
    {512, 4},
    {640, 4},
    {768, 4},
    {1024, 8}
};


s16 mem_init()
{
    s16 ret = rok;
    s16 i;

    bzero(&mem_pool, sizeof(mem_pool_t));

    if(mem_pool.init == true)
    {
        dbg(WS_INFO, "already init.\n");
        return rok;
    }

    mem_pool.subpool = calloc(arr_size(mem_cfg), sizeof(sub_pool_t));
    if(!mem_pool.subpool)
    {
        dbg(WS_ERR, "failed to allocated memory for pool!\n");
        return rfail;
    }

    for(i = 0 ; i < arr_size(mem_cfg) ; i++)
    {
        ret = subpool_init(i);
        if(ret != rok)
        {
            dbg(WS_ERR, "failed to init subpool %d.\n", i);
            goto _out;
        }
    }

    mem_pool.init = true;
    
 _out:
    if(ret != rok)
    {
        while(--i >= 0)
            subpool_deinit(i);

        free(mem_pool.subpool);
    }

    return ret;
}


static s16 subpool_init(s16 idx)
{
    cache_t* c = NULL;
    s16 i;

    sub_pool_t* sp = mem_pool.subpool+idx;

    INIT_LIST_HEAD(&(sp->cache_head));
    sp->cap = mem_cfg[idx].cap;
    sp->blk_sz = mem_cfg[idx].blk_sz;

    for(i = 0 ; i < sp->cap ; i++)
    {
        c = alloc_cache(sp);
        if(!c) 
            break;
        sp->curr_cap++;
    }

    return c ? rok : rfail;
}


static cache_t* alloc_cache(sub_pool_t* sp)
{
    s16 i;

    cache_t* c = calloc(1, CACHE_SIZE);

    if(!c)
    {
        dbg(WS_ERR, "failed to alloc cache subpool %p.\n", sp);
        return NULL;
    }
    /* link this cache to subpool */
    list_add(&(c->cache_list), &(sp->cache_head));
    c->sp = sp;
    c->n_blk = c->n_free_blk = (CACHE_SIZE - sizeof(cache_t)) / 
               (sp->blk_sz + sizeof(mem_blk_t));

    for(i = 0 ; i < c->n_blk ; i++)
    {
        mem_blk_t* mb = (mem_blk_t*)((char*)c + sizeof(cache_t) 
                                     + i*(sp->blk_sz + sizeof(mem_blk_t)));

        mb->owner = c;
        mb->next = c->avail_blk;
        c->avail_blk = mb;
    } 

    return c;
}


static void subpool_deinit(s16 idx)
{
    sub_pool_t* sp = mem_pool.subpool+idx;
    cache_t* cache;
    cache_t* tmp;

    list_for_each_entry_safe(cache, tmp, &(sp->cache_head), cache_list)
    {
        list_del(&cache->cache_list);
        free(cache);
        dbg(WS_INFO, "free cache %p for subpool: %d.\n", cache, idx);
	    sp->curr_cap--;
    }

    assert(sp->curr_cap == 0);
}


void mem_deinit()
{
    s16 i;

    assert(mem_pool.init);

    for(i = 0 ; i < arr_size(mem_cfg) ; i++)
        subpool_deinit(i);

    free(mem_pool.subpool);
}


void* mem_alloc_real(s32 size, const s8* file, const s8* func, s32 line)
{
    s16 i;
    sub_pool_t* sp = NULL;
    cache_t* c;
    s16 found = false;

    assert(mem_pool.init);

    for(i = 0 ; i < arr_size(mem_cfg) ; i++)
    {
        if(size <= mem_cfg[i].blk_sz)
        {
            sp = mem_pool.subpool + i;
            break;
        }
    }

    if(sp)
    {
        dbg(WS_INFO, "[%s:%s:%d] alloc memory size %d from subpool %d.\n", file, func, line, size, i);
        list_for_each_entry(c, &(sp->cache_head), cache_list)
        {
            if(c->n_free_blk == 0)
            {
                assert(c->avail_blk == NULL);
                dbg(WS_INFO, "cache %p is full, search next.\n", c);
            }
            else
            {
                found = true;
                break;
            }
        }

        if(found)              
        {
            return alloc_blk(c);
        }
        else
        {
            /* no cache available */
            c = alloc_cache(sp);
            if(!c)
            {
                dbg(WS_ERR, "failed to alloc memory.\n");
                return NULL;
            }
            else
            {
                dbg(WS_DBG, "allocted new cache %p.\n", c);
                sp->n_ext_alloc++;
                sp->curr_cap++;
                return alloc_blk(c);
            }
        }
    }
    else
    {
        dbg(WS_WARN, "[%s:%s:%d] large memory %d, alloc through malloc.\n", file, func, line, size);
        mem_pool.n_sys_alloc++;
        mem_blk_t* lm = (mem_blk_t*)malloc(size + sizeof(mem_blk_t));
        if(lm == NULL)
            return NULL;
        lm->owner = NULL;
        lm->next = NULL;
        return lm->data;
    }

    return malloc(size);
}


static void* alloc_blk(cache_t* c)
{
    mem_blk_t* blk = NULL;

    assert(c->avail_blk != NULL);

    blk = c->avail_blk;
    c->avail_blk = blk->next;
    blk->next = NULL;
    assert(blk->owner == c);
    c->n_free_blk--;

    /* put full cache to tail */
    if(c->n_free_blk == 0)
    {
        list_del(&(c->cache_list));
        list_add_tail(&(c->cache_list), &(c->sp->cache_head));
    }

    return (void*)blk->data;
}

void mem_free_real(void* p, const s8* file, const s8* func, s32 line)
{
    assert(mem_pool.init);

    mem_blk_t* blk = (mem_blk_t*)((s8*)p - offsetof(mem_blk_t, data));
    cache_t* c = blk->owner;

    if(c == NULL)
    {
        assert(blk->next == NULL);
        dbg(WS_DBG, "[%s:%s:%d] free large memory to system.\n", file, func, line);
        free((void*)blk);
        return;
    }

    assert(c->n_free_blk < c->n_blk);
    blk->next = c->avail_blk;
    c->avail_blk = blk;
    c->n_free_blk++;

    dbg(WS_DBG, "[%s:%s:%d] free memory from subpool %p.\n", file, func, line, c->sp);

    if(c->n_free_blk == c->n_blk)
    {
        dbg(WS_INFO, "cache %p is full of available memory.\n", c);

        if(c->sp->curr_cap > 2*c->sp->cap)
        {
            dbg(WS_INFO, "subpool %p return cache %p to system.\n", c->sp, c);
            list_del(&(c->cache_list));
            c->sp->curr_cap--;
            free(c);
        }
    }
}

#endif
