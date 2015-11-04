#ifndef __TCP_STALL_STATE_H__
#define __TCP_STALL_STATE_H__

#include "tcp_base.h"
#include "list.h"
#include <stdio.h>

struct tcp_state;

struct tcp_stall_state {
	int init_rwnd;
	int max_snd_seg_size;

	int rwnd;
	int ca_state;

	//double cur_time;
	double duration;
	double srtt;
	double rto;
	//double real_rto;


	uint32_t snd_una;
	uint32_t snd_nxt;

	int packets_out;
	int sacked_out;
	int holes;
	int outstanding;
	int lost;
	int spurious;
	int flow_size;

	int tail;
	int head;
	int cur_pkt_dir;
	int cur_pkt_len;
	uint32_t cur_pkt_seq;
	int last_pkt_dir;
	int cur_pkt_spurious_num;
	int cur_pkt_lost_num;

	struct list_head list;
};

void init_tcp_stall(struct tcp_state *ts, struct tcp_stall_state *tss, double duration, int dir, int len, uint32_t seq, double real_rto);
void fill_tcp_stall_list(struct tcp_state *ts, struct list_head *stall_list);
void dump_tss_info(FILE *fp, struct tcp_stall_state *tss);

#endif
