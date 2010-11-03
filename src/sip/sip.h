/**
 * @file sip.h  SIP Private Interface
 *
 * Copyright (C) 2010 Creytiv.com
 */


struct sip {
	struct list transpl;
	struct list lsnrl;
	struct list reql;
	struct hash *ht_ctrans;
	struct hash *ht_strans;
	struct hash *ht_conn;
	struct dnsc *dnsc;
	char *software;
	sip_exit_h *exith;
	void *arg;
	bool closing;
};


struct sip_lsnr {
	struct le le;
	struct sip_lsnr **lsnrp;
	sip_msg_h *msgh;
	void *arg;
	bool req;
};


/* request */
void sip_request_close(struct sip *sip);


/* ctrans */
struct sip_ctrans;

int  sip_ctrans_request(struct sip_ctrans **ctp, struct sip *sip,
			enum sip_transp tp, const struct sa *dst, char *met,
			char *branch, struct mbuf *mb, sip_resp_h *resph,
			void *arg);
int  sip_ctrans_cancel(struct sip_ctrans *ct);
int  sip_ctrans_init(struct sip *sip, uint32_t sz);
int  sip_ctrans_debug(struct re_printf *pf, const struct sip *sip);


/* strans */
int  sip_strans_init(struct sip *sip, uint32_t sz);
int  sip_strans_debug(struct re_printf *pf, const struct sip *sip);


/* transp */
struct sip_connqent;

typedef void(sip_transp_h)(int err, void *arg);

int  sip_transp_init(struct sip *sip, uint32_t sz);
int  sip_transp_send(struct sip_connqent **qentp, struct sip *sip, void *sock,
		     enum sip_transp tp, const struct sa *dst, struct mbuf *mb,
		     sip_transp_h *transph, void *arg);
int  sip_transp_laddr(struct sip *sip, struct sa *laddr, enum sip_transp tp,
		      const struct sa *dst);
bool sip_transp_supported(struct sip *sip, enum sip_transp tp, int af);
const char *sip_transp_srvid(enum sip_transp tp);
bool sip_transp_reliable(enum sip_transp tp);
uint16_t sip_transp_port(enum sip_transp tp, uint16_t port);
int  sip_transp_debug(struct re_printf *pf, const struct sip *sip);


/* auth */
int  sip_auth_encode(struct mbuf *mb, struct sip_auth *auth, const char *met,
		     const char *uri);


/* dialog */
int  sip_dialog_encode(struct mbuf *mb, struct sip_dialog *dlg, uint32_t cseq,
		       const char *met);
const char *sip_dialog_uri(const struct sip_dialog *dlg);
const struct uri *sip_dialog_route(const struct sip_dialog *dlg);
