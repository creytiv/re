/**
 * @file bfcp.h Internal interface to Binary Floor Control Protocol (BFCP)
 *
 * Copyright (C) 2010 Creytiv.com
 */


/* header */
enum {
	BFCP_HDR_SIZE = 12,
	ATTR_HDR_SIZE = 2
};


struct bfcp_hdr {
	uint8_t ver;
	unsigned i:1;
	enum bfcp_prim prim;
	uint16_t len;
	uint32_t confid;
	uint16_t tid;
	uint16_t userid;
};

int bfcp_hdr_encode(struct mbuf *mb, enum bfcp_prim prim, uint16_t len,
		    uint32_t confid, uint16_t tid, uint16_t userid);
int bfcp_hdr_decode(struct mbuf *mb, struct bfcp_hdr *hdr);


/* attributes */
int  bfcp_attr_encode(struct mbuf *mb, bool mand, enum bfcp_attrib type,
		      const void *v);
int  bfcp_attr_decode(struct bfcp_attr **attrp, struct mbuf *mb);
int  bfcp_attr_print(struct re_printf *pf, const struct bfcp_attr *a);
bool bfcp_attr_isgrouped(enum bfcp_attrib attr);


/* socket */

struct bfcp_sock {
	struct list transl;
	struct list connl;
	struct tcp_sock *ts;
	struct tls *tls;
	enum bfcp_transp transp;
	uint16_t tidc;
	bool active;
	bfcp_msg_h *msgh;
	void *arg;
};


int  bfcp_send(struct bfcp_sock *sock, const struct sa *dst, struct mbuf *mb);


/* ctrans request */

void bfcp_ctrans_completed(struct bfcp_ctrans *ct, int err,
			   const struct bfcp_msg *msg);
struct bfcp_ctrans *bfcp_ctrans_find(struct bfcp_sock *sock, uint16_t tid);
