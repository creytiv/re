/**
 * @file re_ice.h  Interface to Interactive Connectivity Establishment (ICE)
 *
 * Copyright (C) 2010 Creytiv.com
 */


/** ICE mode */
enum ice_mode {
	ICE_MODE_FULL,
	ICE_MODE_LITE
};

/** ICE Role */
enum ice_role {
	ICE_ROLE_UNKNOWN = 0,
	ICE_ROLE_CONTROLLING,
	ICE_ROLE_CONTROLLED
};

/** ICE Component ID */
enum ice_compid {
	ICE_COMPID_RTP  = 1,
	ICE_COMPID_RTCP = 2
};

/** ICE Nomination */
enum ice_nomination {
	ICE_NOMINATION_REGULAR = 0,
	ICE_NOMINATION_AGGRESSIVE
};

/** ICE Candidate type */
enum ice_cand_type {
	ICE_CAND_TYPE_HOST,   /**< Host candidate             */
	ICE_CAND_TYPE_SRFLX,  /**< Server Reflexive candidate */
	ICE_CAND_TYPE_PRFLX,  /**< Peer Reflexive candidate   */
	ICE_CAND_TYPE_RELAY   /**< Relayed candidate          */
};

/** ICE TCP protocol type */
enum ice_tcptype {
	ICE_TCP_ACTIVE,   /**< Active TCP client                   */
	ICE_TCP_PASSIVE,  /**< Passive TCP server                  */
	ICE_TCP_SO        /**< Simultaneous-open TCP client/server */
};

/** Candidate pair states */
enum ice_candpair_state {
	ICE_CANDPAIR_FROZEN = 0, /**< Frozen state (default)                 */
	ICE_CANDPAIR_WAITING,    /**< Waiting to become highest on list      */
	ICE_CANDPAIR_INPROGRESS, /**< In-Progress state;transac. in progress */
	ICE_CANDPAIR_SUCCEEDED,  /**< Succeeded state; successful result     */
	ICE_CANDPAIR_FAILED      /**< Failed state; check failed             */
};

struct ice;
struct ice_cand;
struct icem;
struct turnc;

/** ICE Configuration */
struct ice_conf {
	enum ice_nomination nom;  /**< Nomination algorithm        */
	uint32_t rto;             /**< STUN Retransmission TimeOut */
	uint32_t rc;              /**< STUN Retransmission Count   */
	bool debug;               /**< Enable ICE debugging        */
};

typedef void (ice_connchk_h)(int err, bool update, void *arg);


/* ICE Media */
int  icem_alloc(struct icem **icemp, enum ice_mode mode,
		enum ice_role role, int proto, int layer,
		uint64_t tiebrk, const char *lufrag, const char *lpwd,
		ice_connchk_h *chkh, void *arg);
struct ice_conf *icem_conf(struct icem *icem);
enum ice_role icem_local_role(const struct icem *icem);
void icem_set_conf(struct icem *icem, const struct ice_conf *conf);
void icem_set_role(struct icem *icem, enum ice_role role);
void icem_set_name(struct icem *icem, const char *name);
int  icem_comp_add(struct icem *icem, unsigned compid, void *sock);
int  icem_cand_add(struct icem *icem, unsigned compid, uint16_t lprio,
		   const char *ifname, const struct sa *addr);

int  icem_lite_set_default_candidates(struct icem *icem);
bool icem_verify_support(struct icem *icem, unsigned compid,
			 const struct sa *raddr);
int  icem_conncheck_start(struct icem *icem);
void icem_conncheck_stop(struct icem *icem, int err);
int  icem_add_chan(struct icem *icem, unsigned compid, const struct sa *raddr);
bool icem_mismatch(const struct icem *icem);
void icem_update(struct icem *icem);
int  ice_sdp_decode(struct icem *ice, const char *name, const char *value);
int  icem_sdp_decode(struct icem *icem, const char *name, const char *value);
int  icem_debug(struct re_printf *pf, const struct icem *icem);
struct list *icem_lcandl(const struct icem *icem);
struct list *icem_rcandl(const struct icem *icem);
struct list *icem_checkl(const struct icem *icem);
struct list *icem_validl(const struct icem *icem);
const struct sa *icem_cand_default(struct icem *icem, unsigned compid);
const struct sa *icem_selected_laddr(const struct icem *icem, unsigned compid);
const struct ice_cand *icem_selected_lcand(const struct icem *icem,
				unsigned compid);
const struct ice_cand *icem_selected_rcand(const struct icem *icem,
				unsigned compid);
void ice_candpair_set_states(struct icem *icem);
void icem_cand_redund_elim(struct icem *icem);
int  icem_comps_set_default_cand(struct icem *icem);
struct stun *icem_stun(struct icem *icem);
int icem_set_turn_client(struct icem *icem, unsigned compid,
			 struct turnc *turnc);


bool ice_remotecands_avail(const struct icem *icem);
int  ice_cand_encode(struct re_printf *pf, const struct ice_cand *cand);
int  ice_remotecands_encode(struct re_printf *pf, const struct icem *icem);
struct ice_cand *icem_cand_find(const struct list *lst, unsigned compid,
				const struct sa *addr);
int icem_lcand_add(struct icem *icem, struct ice_cand *base,
		   enum ice_cand_type type,
		   const struct sa *addr);
struct ice_cand *icem_lcand_base(struct ice_cand *lcand);
const struct sa *icem_lcand_addr(const struct ice_cand *cand);
enum ice_cand_type icem_cand_type(const struct ice_cand *cand);


extern const char ice_attr_cand[];
extern const char ice_attr_lite[];
extern const char ice_attr_mismatch[];
extern const char ice_attr_pwd[];
extern const char ice_attr_remote_cand[];
extern const char ice_attr_ufrag[];


const char        *ice_cand_type2name(enum ice_cand_type type);
enum ice_cand_type ice_cand_name2type(const char *name);
const char    *ice_role2name(enum ice_role role);
const char    *ice_candpair_state2name(enum ice_candpair_state st);


uint32_t ice_cand_calc_prio(enum ice_cand_type type, uint16_t local,
			    unsigned compid);


/** Defines an SDP candidate attribute */
struct ice_cand_attr {
	char foundation[32];      /**< Foundation string                    */
	unsigned compid;          /**< Component ID (1-256)                 */
	int proto;                /**< Transport protocol                   */
	uint32_t prio;            /**< Priority of this candidate           */
	struct sa addr;           /**< Transport address                    */
	enum ice_cand_type type;  /**< Candidate type                       */
	struct sa rel_addr;       /**< Related transport address (optional) */
	enum ice_tcptype tcptype; /**< TCP candidate type (TCP-only)        */
};

int ice_cand_attr_encode(struct re_printf *pf,
			 const struct ice_cand_attr *cand);
int ice_cand_attr_decode(struct ice_cand_attr *cand, const char *val);
