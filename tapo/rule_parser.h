#ifndef __RULE_PARSER_H__
#define __RULE_PARSER_H__

#include "tcp_stall_state.h"
extern const char *stall_details[];
extern const char *stall_text[];
extern enum stall_type parse_stall(struct tcp_stall_state *);
enum stall_type {
	DATA_UNAVAILABLE, PACKET_DELAY, ZERO_RWND, RETRANS_INIT_RWND_LIMITED, TAIL_RETRANS, CLIENT_IDLE, SMALL_RETRANS_CWND_LIMITED_IN, SMALL_RETRANS_CWND_LIMITED_OUT, SMALL_RETRANS_RWND_LIMITED, RETRANS_DOUBLE, RETRANS_ACK_DELAY, RETRANS_SERIES_RETRANS, RETRANS_UNKNOWN, RESOURCE_CONSTRAINT, UNKNOWN_ISSUE
};

#endif
