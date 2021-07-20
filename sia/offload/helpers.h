#pragma once

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_errno.h>
#include <rte_lcore.h>

inline rte_hash * create_hashtable(char const * name, uint32_t size, size_t key_len) {
    // h will store the pointer to our new hash
    struct rte_hash *h;

    // initialize parameters for new hash table
    struct rte_hash_parameters hash_params = {0};
    hash_params.name = name;
    hash_params.entries = size * 2; // keep load <50% to avoid excessive collisions
    hash_params.key_len = key_len;
    hash_params.socket_id = rte_socket_id();
    hash_params.hash_func = rte_jhash;
    hash_params.hash_func_init_val = 0;

    // huge performance improvement for deletions:
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT;

    // actually create the table
    // NOT MULTI-THREAD-SAFE
    h = rte_hash_create(&hash_params);

    if (h == NULL) {
        rte_exit(EXIT_FAILURE, "Problem creating hash table (%s) (%i)\n",
                rte_strerror(rte_errno), rte_errno);
    }

    return h;
}
