/**
 * @file icestr.c  ICE Strings
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_list.h>
#include <re_tmr.h>
#include <re_sa.h>
#include <re_stun.h>
#include <re_ice.h>
#include "ice.h"


const char *ice_cand_type2name(enum cand_type type)
{
	switch (type) {

	case CAND_TYPE_HOST:  return "host";
	case CAND_TYPE_SRFLX: return "srflx";
	case CAND_TYPE_PRFLX: return "prflx";
	case CAND_TYPE_RELAY: return "relay";
	default:              return "???";
	}
}


enum cand_type ice_cand_name2type(const struct pl *name)
{
	if (0 == pl_strcasecmp(name, "host"))  return CAND_TYPE_HOST;
	if (0 == pl_strcasecmp(name, "srflx")) return CAND_TYPE_SRFLX;
	if (0 == pl_strcasecmp(name, "prflx")) return CAND_TYPE_PRFLX;
	if (0 == pl_strcasecmp(name, "relay")) return CAND_TYPE_RELAY;

	return (enum cand_type)-1;
}


const char *ice_mode2name(enum ice_mode mode)
{
	switch (mode) {

	case ICE_MODE_FULL: return "Full";
	case ICE_MODE_LITE: return "Lite";
	default:            return "???";
	}
}


const char *ice_role2name(enum role role)
{
	switch (role) {

	case ROLE_UNKNOWN:     return "Unknown";
	case ROLE_CONTROLLING: return "Controlling";
	case ROLE_CONTROLLED:  return "Controlled";
	default:               return "???";
	}
}


const char *ice_candpair_state2name(enum candpair_state st)
{
	switch (st) {

	case CANDPAIR_FROZEN:     return "Frozen";
	case CANDPAIR_WAITING:    return "Waiting";
	case CANDPAIR_INPROGRESS: return "InProgress";
	case CANDPAIR_SUCCEEDED:  return "Succeeded";
	case CANDPAIR_FAILED:     return "Failed";
	default:                  return "???";
	}
}


const char *ice_checkl_state2name(enum checkl_state cst)
{
	switch (cst) {

	case CHECKLIST_NULL:      return "(NULL)";
	case CHECKLIST_RUNNING:   return "Running";
	case CHECKLIST_COMPLETED: return "Completed";
	case CHECKLIST_FAILED:    return "Failed";
	default:                  return "???";
	}
}
