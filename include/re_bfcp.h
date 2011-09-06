/**
 * @file re_bfcp.h Interface to Binary Floor Control Protocol (BFCP)
 *
 * Copyright (C) 2010 Creytiv.com
 */


enum {BFCP_VERSION = 1};

/** BFCP Primitives */
enum bfcp_prim {
	BFCP_FLOOR_REQUEST        =  1,
	BFCP_FLOOR_RELEASE        =  2,
	BFCP_FLOOR_REQUEST_QUERY  =  3,
	BFCP_FLOOR_REQUEST_STAT   =  4,
	BFCP_USER_QUERY           =  5,
	BFCP_USER_STATUS          =  6,
	BFCP_FLOOR_QUERY          =  7,
	BFCP_FLOOR_STATUS         =  8,
	BFCP_CHAIR_ACTION         =  9,
	BFCP_CHAIR_ACTION_ACK     = 10,
	BFCP_HELLO                = 11,
	BFCP_HELLO_ACK            = 12,
	BFCP_ERROR                = 13,
};

/** BFCP Attributes */
enum bfcp_attrib {
	BFCP_BENEFICIARY_ID            =  1,
	BFCP_FLOOR_ID                  =  2,
	BFCP_FLOOR_REQUEST_ID          =  3,
	BFCP_PRIORITY                  =  4,
	BFCP_REQUEST_STATUS            =  5,
	BFCP_ERROR_CODE                =  6,
	BFCP_ERROR_INFO                =  7,
	BFCP_PARTICIPANT_PROV_INFO     =  8,
	BFCP_STATUS_INFO               =  9,
	BFCP_SUPPORTED_ATTRIBUTES      = 10,
	BFCP_SUPPORTED_PRIMITIVES      = 11,
	BFCP_USER_DISPLAY_NAME         = 12,
	BFCP_USER_URI                  = 13,
	/* grouped: */
	BFCP_BENEFICIARY_INFO          = 14,
	BFCP_FLOOR_REQUEST_INFO        = 15,
	BFCP_REQUESTED_BY_INFO         = 16,
	BFCP_FLOOR_REQUEST_STATUS      = 17,
	BFCP_OVERALL_REQUEST_STATUS    = 18,
};

/** BFCP Request Status */
enum bfcp_rstat {
	BFCP_PENDING   = 1,
	BFCP_ACCEPTED  = 2,
	BFCP_GRANTED   = 3,
	BFCP_DENIED    = 4,
	BFCP_CANCELLED = 5,
	BFCP_RELEASED  = 6,
	BFCP_REVOKED   = 7
};

/** BFCP Error Codes */
enum bfcp_err {
	BFCP_ERR_CONF_NOT_EXIST         = 1,
	BFCP_ERR_USER_NOT_EXIST         = 2,
	BFCP_ERR_UNKNOWN_PRIM           = 3,
	BFCP_ERR_UNKNOWN_MAND_ATTR      = 4,
	BFCP_ERR_UNAUTH_OPERATION       = 5,
	BFCP_ERR_INVALID_FLOOR_ID       = 6,
	BFCP_ERR_FLOOR_REQ_ID_NOT_EXIST = 7,
	BFCP_ERR_MAX_FLOOR_REQ_REACHED  = 8,
	BFCP_ERR_USE_TLS                = 9
};

enum bfcp_prio {
	BFCP_PRIO_LOWEST  = 0,
	BFCP_PRIO_LOW     = 1,
	BFCP_PRIO_NORMAL  = 2,
	BFCP_PRIO_HIGH    = 3,
	BFCP_PRIO_HIGHEST = 4
};

struct bfcp_reqstat {
	enum bfcp_rstat stat;
	uint8_t qpos;
};

struct bfcp_errcode {
	enum bfcp_err code;
	uint8_t *details;  /* optional */
	size_t len;
};

struct bfcp_supattr {
	enum bfcp_attrib *attrv;
	size_t attrc;
};

struct bfcp_supprim {
	enum bfcp_prim *primv;
	size_t primc;
};

struct bfcp_overall_reqstat {
	uint16_t freqid;
	struct bfcp_reqstat reqstat;
	char *statinfo;
};

struct bfcp_beneficiary_info {
	uint16_t bfid;
	char *dname;
	char *uri;
};

struct bfcp_reqby_info {
	uint16_t rbid;
	char *dname;
	char *uri;
};

struct bfcp_floor_reqstat {
	uint16_t floorid;
	struct bfcp_reqstat reqstat;
	char *statinfo;
};

struct bfcp_floor_reqinfo {
	uint16_t freqid;
	struct bfcp_overall_reqstat ors;
	struct bfcp_floor_reqstat *frsv;
	size_t frsc;
	struct bfcp_beneficiary_info bfi;
	struct bfcp_reqby_info rbi;
	uint8_t prio;
	char *ppi;
};

struct bfcp_attr {
	struct le le;
	enum bfcp_attrib type;
	bool mand;
	union bfcp_union {
		/* generic types */
		char *str;
		uint16_t u16;

		/* actual attributes */
		uint16_t bfid;
		uint16_t floorid;
		uint16_t freqid;
		uint8_t prio;
		struct bfcp_reqstat reqstat;
		struct bfcp_errcode errcode;
		char *errinfo;
		char *ppi;
		char *statinfo;
		struct bfcp_supattr supattr;
		struct bfcp_supprim supprim;
		char *userdname;
		char *useruri;

		/* grouped attributes */
		struct bfcp_beneficiary_info bfi;
		struct bfcp_floor_reqinfo fri;
		struct bfcp_reqby_info rbi;
		struct bfcp_floor_reqstat frs;
		struct bfcp_overall_reqstat ors;
	} v;
};

enum bfcp_transp {
	BFCP_TRANSP_TCP = 0,
	BFCP_TRANSP_TLS = 1
};


/* BFCP Message */

struct bfcp_msg;

typedef bool (bfcp_attr_h)(const struct bfcp_attr *attr, void *arg);

int bfcp_msg_vencode(struct mbuf *mb, enum bfcp_prim prim,
		     uint32_t confid, uint16_t tid, uint16_t userid,
		     uint32_t attrc, va_list ap);
int bfcp_msg_encode(struct mbuf *mb, enum bfcp_prim prim, uint32_t confid,
		    uint16_t tid, uint16_t userid, uint32_t attrc, ...);
int bfcp_msg_decode(struct bfcp_msg **msgp, struct mbuf *mb);
struct bfcp_attr *bfcp_msg_attr(const struct bfcp_msg *msg,
				enum bfcp_attrib type);
struct bfcp_attr *bfcp_msg_attr_apply(const struct bfcp_msg *msg,
				      bfcp_attr_h *h, void *arg);
int bfcp_msg_print(struct re_printf *pf, const struct bfcp_msg *msg);
enum bfcp_prim bfcp_msg_prim(const struct bfcp_msg *msg);
uint32_t bfcp_msg_confid(const struct bfcp_msg *msg);
uint16_t bfcp_msg_tid(const struct bfcp_msg *msg);
uint16_t bfcp_msg_userid(const struct bfcp_msg *msg);
void bfcp_msg_set_src(struct bfcp_msg *msg, const struct sa *src);
const struct sa *bfcp_msg_src(const struct bfcp_msg *msg);


/* BFCP supplement */

const char *bfcp_prim_name(enum bfcp_prim prim);
const char *bfcp_attr_name(enum bfcp_attrib attr);
const char *bfcp_reqstat_name(enum bfcp_rstat rstat);
const char *bfcp_errcode_name(enum bfcp_err code);


/* BFCP Transport */

bool bfcp_transp_reliable(enum bfcp_transp tp);
const char *bfcp_transp_proto(enum bfcp_transp tp);


/* BFCP Socket */

struct tls;
struct bfcp_sock;
struct bfcp_ctrans;

typedef void (bfcp_msg_h)(const struct bfcp_msg *msg, void *arg);
typedef void (bfcp_resp_h)(int err, const struct bfcp_msg *msg, void *arg);


int bfcp_listen(struct bfcp_sock **sockp, enum bfcp_transp transp,
		struct tls *tls, const struct sa *laddr,
		bfcp_msg_h *msgh, void *arg);
int bfcp_request(struct bfcp_ctrans **ctp, struct bfcp_sock *sock,
		 const struct sa *dst,
		 enum bfcp_prim prim, uint32_t confid, uint16_t userid,
		 bfcp_resp_h *resph, void *arg, uint32_t attrc, ...);
int bfcp_reply(struct bfcp_sock *sock, const struct bfcp_msg *req,
	       enum bfcp_prim prim, uint32_t attrc, ...);
int bfcp_ereply(struct bfcp_sock *sock, const struct bfcp_msg *req,
		enum bfcp_err code, ...);
