#include <rte_mbuf.h>

static inline void * rte_mbuf_to_priv(struct rte_mbuf *m) {
	return RTE_PTR_ADD(m, sizeof(struct rte_mbuf));
}
