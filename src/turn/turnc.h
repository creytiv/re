/**
 * @file turnc.h  Internal TURN interface
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <time.h>


struct loop_state {
	uint32_t failc;
	uint16_t last_scode;
};

struct channels;

struct turnc {
	struct loop_state ls;
	struct udp_helper *uh;
	struct stun_ctrans *ct;
	char *username;
	char *password;
	struct sa psrv;
	struct sa srv;
	void *sock;
	int proto;
	struct stun *stun;             /**< STUN Instance                   */
	uint32_t lifetime;             /**< Allocation lifetime in [seconds]*/
	struct tmr tmr;                /**< Allocation refresh timer        */
	turnc_h *th;                   /**< Turn client handler             */
	void *arg;                     /**< Handler argument                */
	uint8_t md5_hash[MD5_SIZE];    /**< Cached MD5-sum of credentials   */
	char *nonce;                   /**< Saved NONCE value from server   */
	char *realm;                   /**< Saved REALM value from server   */
	struct hash *perms;
	struct channels *chans;
	bool allocated;
};


/* Util */
bool turnc_request_loops(struct loop_state *ls, uint16_t scode);
void turnc_loopstate_reset(struct loop_state *ls);
int  turnc_keygen(struct turnc *turnc, const struct stun_msg *msg);


/* Permission */
int turnc_perm_hash_alloc(struct hash **ht, uint32_t bsize);


/* Channels */
enum {
	CHAN_HDR_SIZE = 4,
};

struct chan_hdr {
	uint16_t nr;
	uint16_t len;
};

struct chan;

int turnc_chan_hash_alloc(struct channels **cp, uint32_t bsize);
struct chan *turnc_chan_find_numb(const struct turnc *turnc, uint16_t nr);
struct chan *turnc_chan_find_peer(const struct turnc *turnc,
				  const struct sa *peer);
uint16_t turnc_chan_numb(const struct chan *chan);
const struct sa *turnc_chan_peer(const struct chan *chan);
int turnc_chan_hdr_encode(const struct chan_hdr *hdr, struct mbuf *mb);
int turnc_chan_hdr_decode(struct chan_hdr *hdr, struct mbuf *mb);
