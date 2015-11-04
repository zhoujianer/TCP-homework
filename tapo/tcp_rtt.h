#ifndef __TCP_RTT_H__
#define __TCP_RTT_H__

#include <stdint.h>
#include "list.h"

struct seq_rtt_t
{
	uint32_t ack_seq;
	double time;
	struct list_head list;
};

struct seq_time_t
{
	uint32_t seq;
	double time;
	struct list_head list;
};

void insert_seq_rtt(uint32_t ack_seq, double t, struct list_head *list);
int get_rtt(uint32_t ack, double t, struct list_head *list);
void delete_rtt_list(struct list_head *list);
double get_first_send_time(uint32_t seq, double t, struct list_head *list);

#endif
