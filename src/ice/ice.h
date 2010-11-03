/**
 * @file ice.h  Internal Interface to ICE
 *
 * Copyright (C) 2010 Creytiv.com
 */


#ifndef RELEASE
#define ICE_TRACE 1    /**< Trace connectivity checks */
#endif


enum role {
	ROLE_UNKNOWN = 0,
	ROLE_CONTROLLING,
	ROLE_CONTROLLED
};

enum checkl_state {
	CHECKLIST_NULL = -1,
	CHECKLIST_RUNNING,
	CHECKLIST_COMPLETED,
	CHECKLIST_FAILED
};

enum cand_type {
	CAND_TYPE_HOST,
	CAND_TYPE_SRFLX,
	CAND_TYPE_PRFLX,
	CAND_TYPE_RELAY
};

/** Candidate pair states */
enum candpair_state {
	CANDPAIR_FROZEN = 0, /**< Frozen state (default)                    */
	CANDPAIR_WAITING,    /**< Waiting to become highest on list         */
	CANDPAIR_INPROGRESS, /**< In-Progress state;transaction in progress */
	CANDPAIR_SUCCEEDED,  /**< Succeeded state; successful check result  */
	CANDPAIR_FAILED      /**< Failed state; check failed                */
};

enum ice_transp {
	ICE_TRANSP_NONE = -1,
	ICE_TRANSP_UDP
};

enum {
	ICE_DEFAULT_Tr          =  15,   /* [ms] */
	ICE_DEFAULT_Ta_RTP      =  20,   /* [ms] */
	ICE_DEFAULT_Ta_NON_RTP  = 500,   /* [ms] */
	ICE_DEFAULT_RTO_RTP     = 100,   /* [ms] */
	ICE_DEFAULT_RTO_NONRTP  = 500,   /* [ms] */
	ICE_DEFAULT_RC          =   4
};


/** Defines an ICE session */
struct ice {
	enum ice_mode lmode;          /**< Local mode                       */
	enum ice_mode rmode;          /**< Remote mode                      */
	enum role lrole;              /**< Local role                       */
	char lufrag[5];               /**< Local Username fragment          */
	char lpwd[23];                /**< Local Password                   */
	struct list ml;               /**< Media list (struct icem)         */
	uint64_t tiebrk;              /**< Tie-break value for roleconflict */
};

/** Defines a media-stream component */
struct icem_comp {
	struct le le;                /**< Linked-list element               */
	struct icem *icem;           /**< Parent ICE media                  */
	struct cand *def_cand;       /**< Default candidate                 */
	struct candpair *cp_sel;     /**< Selected candidate-pair           */
	struct udp_helper *uh;       /**< UDP helper                        */
	void *sock;                  /**< Transport socket                  */
	uint16_t lport;              /**< Local port number                 */
	uint8_t id;                  /**< Component ID                      */
	bool concluded;              /**< Concluded flag                    */
	struct turnc *turnc;         /**< TURN Client                        */
	struct stun_ctrans *ct_gath; /**< STUN Transaction for gathering     */
};

/** Defines an ICE media-stream */
struct icem {
	struct le le;                /**< Linked-list element                */
	struct ice *ice;             /**< Pointer to parent ICE-session      */
	struct sa stun_srv;          /**< STUN Server IP address and port    */
	int nstun;                   /**< Number of pending STUN candidates  */
	struct list lcandl;          /**< List of local candidates           */
	struct list rcandl;          /**< List of remote candidates          */
	struct list checkl;          /**< Check List of cand pairs           */
	struct list validl;          /**< Valid List of cand pairs           */
	struct list triggl;          /**< Triggered check-list               */
	bool mismatch;               /**< ICE mismatch flag                  */
	struct tmr tmr_pace;         /**< Timer for pacing STUN requests     */
	struct stun *stun;           /**< STUN Transport                     */
	int proto;                   /**< Transport protocol                 */
	int layer;                   /**< Protocol layer                     */
	enum checkl_state state;     /**< State of the checklist             */
	struct list compl;           /**< ICE media components               */
	char *rufrag;                /**< Remote Username fragment           */
	char *rpwd;                  /**< Remote Password                    */
	ice_gather_h *gh;            /**< Gather handler                     */
	ice_connchk_h *chkh;         /**< Connectivity check handler         */
	void *arg;                   /**< Handler argument                   */
};

/** Defines a candidate */
struct cand {
	struct le le;                /**< List element                       */
	enum cand_type type;         /**< Candidate type                     */
	uint32_t prio;               /**< Priority of this candidate         */
	char *foundation;            /**< Foundation                         */
	uint8_t compid;              /**< Component ID (1-256)               */
	struct sa rel;               /**< Related IP address and port number */
	struct sa addr;              /**< Transport address                  */
	enum ice_transp transp;      /**< Transport protocol                 */
	struct cand *base;           /**< Links to base candidate, if any    */

	/* extra for local */
	char *ifname;                /**< Network interface, for diagnostics */
};

/** Defines a candidate pair */
struct candpair {
	struct le le;                /**< List element                       */
	struct icem *icem;           /**< Pointer to parent ICE media        */
	struct cand *lcand;          /**< Local candidate                    */
	struct cand *rcand;          /**< Remote candidate                   */
	bool def;                    /**< Default flag                       */
	bool valid;                  /**< Valid flag                         */
	bool nominated;              /**< Nominated flag                     */
	enum candpair_state state;   /**< Candidate pair state               */
	uint64_t pprio;              /**< Pair priority                      */
	uint64_t tick_sent;          /**< When connectivity request was sent */
	int rtt;                     /**< Estimated Round-Trip Time in [ms]  */
	bool use_cand;               /**< Use-candidate flag                 */
	struct stun_ctrans *ct_conn; /**< STUN Transaction for conncheck     */
};


/* cand */
int icem_lcand_add_base(struct icem *icem, uint8_t compid, uint16_t lprio,
			const char *ifname, enum ice_transp transp,
			const struct sa *addr);
int icem_lcand_add(struct icem *icem, struct cand *base, enum cand_type type,
		   const struct sa *addr);
int icem_rcand_add(struct icem *icem, enum cand_type type, uint8_t compid,
		   uint32_t prio, const struct sa *addr,
		   const struct sa *rel_addr, const struct pl *foundation);
struct cand *icem_cand_find(const struct list *lst, uint8_t compid,
			    const struct sa *addr);
int icem_cands_debug(struct re_printf *pf, const struct list *lst);
int icem_cand_print(struct re_printf *pf, const struct cand *c);


/* candpair */
int  icem_candpair_alloc(struct candpair **cpp, struct icem *icem,
			 struct cand *lcand, struct cand *rcand);
void icem_candpair_prio_order(struct list *lst);
void icem_candpair_move(struct candpair *cp, struct list *list);
void icem_candpair_cancel(struct candpair *cp);
bool icem_candpair_cmp(const struct candpair *cp1, const struct candpair *cp2);
bool icem_candpair_cmp_fnd(const struct candpair *cp1,
			   const struct candpair *cp2);
struct candpair *icem_candpair_find(const struct list *lst,
				    const struct cand *lcand,
				    const struct cand *rcand);
struct candpair *icem_candpair_find_st(const struct list *lst, uint8_t compid,
				       enum candpair_state state);
int  icem_candpair_debug(struct re_printf *pf, const struct candpair *cp);
int  icem_candpairs_debug(struct re_printf *pf, const struct list *list);


/* stun server */
int icem_stund_recv(struct icem_comp *comp, const struct sa *src,
		    struct stun_msg *req, size_t presz);


/* ICE media */
void icem_cand_redund_elim(struct icem *icem);


/* Checklist */
int  icem_checklist_form(struct icem *icem);
void icem_checklist_update(struct icem *icem);


/* component */
int  icem_comp_alloc(struct icem_comp **cp, struct icem *icem, int id,
		     void *sock);
int  icem_comp_set_default_cand(struct icem_comp *comp);
void icem_comp_set_selected(struct icem_comp *comp, struct candpair *cp);
struct icem_comp *icem_comp_find(const struct icem *icem, uint8_t compid);


/* conncheck */
int  icem_conncheck_start(struct icem *icem);
void icem_conncheck_schedule_check(struct icem *icem);


/* triggered check queue */
void icem_triggq_push(struct icem *icem, struct candpair *cp);
struct candpair *icem_triggq_pop(struct icem *icem);


/* icestr */
const char    *ice_cand_type2name(enum cand_type type);
enum cand_type ice_cand_name2type(const struct pl *name);
const char    *ice_mode2name(enum ice_mode mode);
const char    *ice_role2name(enum role role);
const char    *ice_candpair_state2name(enum candpair_state st);
const char    *ice_checkl_state2name(enum checkl_state cst);


/* util */
typedef void * (list_unique_h)(struct le *le1, struct le *le2);

uint32_t ice_calc_prio(enum cand_type type, uint16_t local, uint8_t compid);
uint64_t ice_calc_pair_prio(uint32_t g, uint32_t d);
void ice_switch_local_role(struct ice *ice);
uint32_t ice_list_unique(struct list *list, list_unique_h *uh);
