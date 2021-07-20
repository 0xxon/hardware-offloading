#include <iostream>

#include <assert.h>

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include <config.h>
#include <debug.h>
#include <tcp.h>
#include <offload.h>
#include <offload_stats.h>
#include <helpers.h>

//// Function definitions

offload * offload_create(rte_mempool *pktmbuf_pool) {
    // Allocate a new offload struct
    offload *o = (offload *)rte_zmalloc(NULL, sizeof(struct offload),
            RTE_CACHE_LINE_SIZE);

    char hname[RTE_HASH_NAMESIZE];
    snprintf(hname, sizeof(hname), "offload_lcore_%u", rte_lcore_id());

    o->hash = create_hashtable(hname, OFFLOAD_TABLE_SIZE, sizeof(struct tcp_conn));

    char pname[32];
    snprintf(pname, sizeof(pname), "offl_pool_lcore_%u", rte_lcore_id());

    o->pool = rte_mempool_create(
            pname,
            OFFLOAD_TABLE_SIZE,
            sizeof(struct offload_pkt_data),
            512,
            0,
            NULL, NULL,
            NULL, NULL,
            rte_socket_id(),
            0);

    if (o->pool == NULL) {
        rte_exit(EXIT_FAILURE, "Error creating offload packet data pool"
                " (%s)\n", rte_strerror(rte_errno));
    }

    o->pktmbuf_pool = pktmbuf_pool;

#ifdef ENABLE_OFFLOAD_STATS
    o->stats = offload_stats_create(o);
#else
    o->stats = NULL;
#endif

    return o;
}

static offload_pkt_data * offload_load_mbuf(offload *o, rte_mbuf *m) {
    int ret;
    offload_pkt_data *data = NULL;

    // TODO: for performance, could use a local cache and use mempool bulk ops
    ret = rte_mempool_get(o->pool, (void**)&data);

    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to allocate offload entry.");
    }

    // get packet size in bytes
    data->data_len = rte_pktmbuf_data_len(m);

    // ensure the mbuf data len does not exceed our struct size
    assert(data->data_len <= sizeof(struct offload_pkt_data_inner));

    // Packet must be contiguous (i.e. NOT segmented)
    assert(rte_pktmbuf_is_contiguous(m));

    // Load ethernet, IP, and TCP headers (i.e. clone the packet)
    rte_memcpy(&data->inner_data, rte_pktmbuf_mtod(m, void*), data->data_len);

    // Load timestamp
    data->timestamp = m->udata64;

    // Add mempool
    data->pool = o->pool;

    return data;
}

rte_mbuf * offload_make_mbuf(offload *o, offload_pkt *p) {
    rte_mbuf *m = rte_pktmbuf_alloc(o->pktmbuf_pool);
    void *m_data;

    if (m == NULL) {
        rte_exit(EXIT_FAILURE, "offload_make_mbuf could not allocate mbuf");
    }

    m_data = rte_pktmbuf_append(m, p->data->data_len);

    assert( /* maximum size of all headers + trailers */
            sizeof(struct offload_pkt_data_inner)
            /* minus *unused* section of TCP opts */
            - (60 - ((p->data->inner_data.tcp.data_off & 0xf0) >> 2))
            /* should equal the length of the data in our packet */
            == p->data->data_len );

    // Copy the offload packet data into the mbuf
    // NOTE: the only reason why we can copy the struct directly like this is
    // because it's a tightly-packed struct
    assert(p->data->data_len <= sizeof(p->data->inner_data));
    rte_memcpy(m_data, &p->data->inner_data, p->data->data_len);

    // Copy the timestamp metadata
    m->udata64 = p->data->timestamp;

#ifdef DEBUG
    rte_mbuf_sanity_check(m, true);
#endif

    return m;
}

offload_pkt * offload_insert(offload *o, tcp_conn *c, rte_mbuf *m) {
    hash_sig_t hs = offload_hash_sig(o, c);
    return offload_insert(o, c, m, hs);
}

offload_pkt * offload_insert(offload *o, tcp_conn *c, rte_mbuf *m, hash_sig_t hs) {
    // If it already exists, remove the old one
    offload_pkt *old = offload_lookup(o, c, hs);
    if (old != NULL) {
        if (!tcp_conn_eq(&old->conn, c)) {
            std::cerr << "offload_insert: HASH COLLISION!!!\n";
        }
#ifdef DEBUG_ENABLE
        // Debug: check if we have a collision
        if (!tcp_conn_eq(&old->conn, c)) {
            DEBUG("offload_insert: HASH COLLISION!!!\n");
        } else {
            DEBUG("offload_insert: found duplicate, removing old entry\n");
        }
#endif
        // remove and free the old packet data
        if (o->stats != NULL)
            offload_stats_handle(o->stats, old->data);
        offload_remove(o, old, hs, true);
    }

    // If table is full, first remove tail
    if (o->len == OFFLOAD_TABLE_SIZE) {
        DEBUG("offload_insert: OFFLOAD TABLE FULL... REMOVING OLDEST\n");
        if (o->stats != NULL)
            offload_stats_handle(o->stats, o->tail->data);
        offload_remove(o, o->tail, o->tail->hs, true);
        o->drop_count++;
    }

    // Do the hashtable insertion
    int32_t idx = rte_hash_add_key_with_hash(o->hash, c, hs);
    if (idx == -ENOSPC) {
        rte_exit(EXIT_FAILURE, "Hash insertion error (-ENOSPC)");
    }
    if (idx == -EINVAL) {
        rte_exit(EXIT_FAILURE, "Hash insertion error (-EINVAL)");
    }
    if (idx < 0) {
        rte_exit(EXIT_FAILURE, "Hash insertion error");
    }

    // Now insert into the linkedlist
    o->entries[idx] = {
        .conn = *c,
        .hs = hs,
        .data = offload_load_mbuf(o, m),
        .next = NULL,
        .prev = o->head,
    };

    // Add stats hash
    if (o->stats != NULL)
        o->entries[idx].data->stats_key_hash = offload_stats_hash(c);

    if (o->head != NULL) {
        o->head->next = &o->entries[idx];
    }

    o->head = &o->entries[idx];

    if (o->tail == NULL) {
        o->tail = o->head;
    }

    o->len++;
    DEBUG("offload_insert: TABLE SIZE %u\n", o->len);
    return o->head;
}

offload_pkt * offload_lookup(offload *o, tcp_conn *c) {
    hash_sig_t hs = offload_hash_sig(o, c);
    return offload_lookup(o, c, hs);
}

offload_pkt * offload_lookup(offload *o, tcp_conn *c, hash_sig_t hs) {
    int ret = rte_hash_lookup_with_hash(o->hash, c, hs);
    return (ret < 0) ? NULL : &o->entries[ret];
}

void offload_remove(offload *o, offload_pkt *p, bool free_data) {
    offload_remove(o, p, p->hs, free_data);
}

void offload_remove(offload *o, offload_pkt *p, hash_sig_t hs, bool free_data) {
    if (p == NULL) {
        return;
    }

    // Delete from hash
    int ret = rte_hash_del_key_with_hash(o->hash, &p->conn, hs);

#ifdef DEBUG_ENABLE
    if (o->len == 0) {
        rte_exit(EXIT_FAILURE, 
                "DEBUG: Remove from empty offload table");
    }
    if (&o->entries[ret] != p) {
        rte_exit(EXIT_FAILURE, 
                "DEBUG: Mismatch when trying to remove offload packet");
    } 
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, 
                "DEBUG: Tried to remove non-existent offload packet");
    }
#endif

    // if the entry doesn't exist, just do nothing
    if (ret == -EINVAL) {
        rte_exit(EXIT_FAILURE, "INVALID HASH DELETE");
    }
    if (ret < 0) {
        return; 
    }

    // Remove from linked list
    // Update prev and next packets
    if (p->prev != NULL) {
        p->prev->next = p->next;
    }
    if (p->next != NULL) {
        p->next->prev = p->prev;
    }

    // Update head and tail pointers if we removed the head or tail
    if (o->head == p) {
        o->head = p->prev;
    } 
    if (o->tail == p) {
        o->tail = p->next;
    }

    // free the data struct back to the mempool
    if (free_data)
        rte_mempool_put(o->pool, p->data);

    // Successfully removed, decrement table size counter
    o->len--;

    DEBUG("offload_remove: TABLE SIZE %u\n", o->len);
}

void offload_remove(offload *o, tcp_conn *c, bool free_data) {
    hash_sig_t hs = offload_hash_sig(o, c);
    return offload_remove(o, c, hs, free_data);
}

void offload_remove(offload *o, tcp_conn *c, hash_sig_t hs, bool free_data) {
    return offload_remove(o, offload_lookup(o, c, hs), hs, free_data);
}

void offload_print_table(offload *o) {
    printf("offload_print_table {\n");
    if (o->len == 0) {
        printf("  empty\n");
        printf("} offload_print_table\n");
        return;
    }

    unsigned int count = 0;
    offload_pkt *entry = o->tail;

    while(entry != NULL) {
        if (entry == o->head) {
            printf("  HEAD ");
        }
        if (entry == o->tail) {
            printf("  TAIL ");
        }
        char orig_ip_str[INET_ADDRSTRLEN];
        tcp_ipv4_pkt_addr_to_str(entry->conn.orig.ip, orig_ip_str);
        char dest_ip_str[INET_ADDRSTRLEN];
        tcp_ipv4_pkt_addr_to_str(entry->conn.dest.ip, dest_ip_str);
        printf("  %u:%p {\n"
               "    conn = {orig=%s:%u, dest=%s:%u}\n"
               /* "    m = %s\n" */
               "    next = %p\n"
               "    prev = %p\n"
               "  }\n",
               count, entry,
               orig_ip_str, rte_be_to_cpu_16(entry->conn.orig.port),
               dest_ip_str, rte_be_to_cpu_16(entry->conn.dest.port),
               /* rte_get_ptype_l4_name(entry->m->packet_type), */
               entry->next,
               entry->prev);
        entry = entry->next;
        count++;
    }
    printf("} offload_print_table\n");
}

void offload_get_stats(offload *o, offload_printstats *s) {
    s->size = o->len;
    s->capacity = OFFLOAD_TABLE_SIZE;
    s->drop_cnt = o->drop_count;
    if (o->tail != NULL && o->tail->data != NULL)
        s->oldest_ts = o->tail->data->timestamp;
    else
        s->oldest_ts = 0;
    if (o->head != NULL && o->head->data != NULL)
        s->newest_ts = o->head->data->timestamp;
    else
        s->newest_ts = 0;
}
