#include "tcp_state.h"
#include "tcp_base.h"
#include "tcp_rtt.h"
#include "malloc.h"
#include "tcp_sack.h"
#include "tcp_stall_state.h"
#include "rule_parser.h"
#include "log.h"
#include "def.h"
#include "cmd_options.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

const char *tcp_ca_state[] = { "TCP_CA_OPEN", "TCP_CA_RECOVERY" };

// valid state: TCP_CLOSE, TCP_SYN_RECV, TCP_SYN_SENT, TCP_ESTABLISHED, TCP_FIN_WAIT1, TCP_FIN_WAIT2 }
// 				TCP_LISTEN

struct tcp_state *new_tcp_state(struct tcp_key *key, double time)
{
	struct tcp_state *ts = MALLOC(struct tcp_state);

	// all the variables have been set to 0

	memcpy(&ts->key, key, sizeof(struct tcp_key));
	sprintf(ts->name, "%s.%hu", inet_ntoa(key->addr[1]), ntohs(key->port[1]));
	ts->rwnd_scale = 1;
	ts->state = TCP_LISTEN;
	ts->file_num = 0;
	ts->tail_burst = 0;

	init_rtt(&ts->rtt);

	init_list_head(&ts->rtt_list);
	init_list_head(&ts->block_list);
	init_list_head(&ts->retrans_list);
	init_list_head(&ts->reordering_list);
	init_list_head(&ts->spurious_retrans_list);
	init_list_head(&ts->lost_list);
	init_list_head(&ts->send_out_time_list);
	init_list_head(&ts->srtt_list);

	init_list_head(&ts->stall_list);

	return ts;
}

static void update_reordering(struct tcp_state *ts, uint32_t b, uint32_t e)
{
	if (ts->reord.begin == 0) {
		ts->reord.begin = b;
		ts->reord.end = e;
	}
	else {
		if (after(b, ts->reord.end)) {
			append_to_range_list(&ts->reordering_list, 
					ts->reord.begin, ts->reord.end); 
			ts->reord.begin = b;
			ts->reord.end = e;
		}
		else if (after(ts->reord.begin, e)) {
			LOG(DEBUG, "invalid reordering range.\n");
		}
		else {
			if (before(b, ts->reord.begin))
				ts->reord.begin = b;
			if (after(e, ts->reord.end))
				ts->reord.end = e;
		}
	}
}

// this function should be called when sweeping the flow
static void get_lost_list(struct tcp_state *ts)
{
	struct list_head *retrans = &ts->retrans_list, 
					 *spurious_retrans = &ts->spurious_retrans_list, 
					 *lost = &ts->lost_list;

	struct list_head *xp = retrans->next, 
					 *rp = spurious_retrans->next;
	struct range_t *xr, *rr;
	while (xp != retrans && rp != spurious_retrans) {
		xr = list_entry(xp, struct range_t, list);
		rr = list_entry(rp, struct range_t, list);

		if (before(xr->begin, rr->begin)) {
			// xr is lost
			append_to_range_list(lost, xr->begin, xr->end);
			xp = xp->next;
		}
		else if (!before(xr->begin, rr->end)) {
			rp = rp->next;
		}
		else {
			xp = xp->next;
		}
	}

	while (xp != retrans) {
		xr = list_entry(xp, struct range_t, list);
		append_to_range_list(lost, xr->begin, xr->end);
		xp = xp->next;
	}
}

static void get_reord_list(struct tcp_state *ts)
{
	struct list_head *reord_node = ts->reordering_list.next,
					 *lost_node = ts->lost_list.next,
					 *block_node = ts->block_list.next;
	struct range_t *reord, *lost, *block;
	while (reord_node != &ts->reordering_list && 
			lost_node != &ts->lost_list) {
		reord = list_entry(reord_node, struct range_t, list);
		lost = list_entry(lost_node, struct range_t, list);

		if (!after(reord->end, lost->begin))
			reord_node = reord_node->next;
		else if (!after(lost->end, reord->begin))
			lost_node = lost_node->next;
		else {
			if (after(lost->begin, reord->begin)) {
				// lost does not cover the front part of reord
				struct range_t *new = MALLOC(struct range_t);
				new->begin = reord->begin;
				new->end = lost->begin;
				list_insert(&new->list, reord_node->prev, reord_node);
			}

			if (before(lost->end, reord->end)) {
				// lost does not cover the tail part of reord
				struct range_t *new = MALLOC(struct range_t);
				new->begin = lost->end;
				new->end = reord->end;
				list_insert(&new->list, reord_node, reord_node->next);
			}

			// delete the reord node
			reord_node = reord_node->next;
			list_delete_entry(reord_node->prev);
			FREE(reord);

			lost_node = lost_node->next;
		}
	}

	reord_node = ts->reordering_list.next;
	block_node = ts->block_list.next;
	while (reord_node != &ts->reordering_list && 
			block_node != &ts->block_list) {
		reord = list_entry(reord_node, struct range_t, list);
		block = list_entry(block_node, struct range_t, list);
		if (after(block->begin, reord->end)) {
			reord_node = reord_node->next;
			continue;
		}

		if (after(reord->begin, block->end)) {
			block_node = block_node->next;
			continue;
		}

		if (!after(block->begin, reord->begin)) {
			reord->begin = block->end;			
		}
		if (!before(block->end, reord->end)) {
			reord->end = block->begin;
		}

		reord_node = reord_node->next;
		if ((int)(reord->end - reord->begin) <= (int)(ts->max_snd_seg_size)) {
			list_delete_entry(reord_node->prev);
			FREE(reord);
		}
	}
}

static void handle_in_pkt(struct tcp_state *ts, struct tcphdr *th, double time, int len)
{
	uint32_t seq = ntohl(th->seq),
			 ack_seq = ntohl(th->ack_seq);
	if (IS_SYN(th)) {
		ts->rwnd_scale = (1 << ts->option.wscale);
		ts->init_rwnd = ntohs(th->window) * ts->rwnd_scale;
	}
	if ((ts->snd_nxt != 0) && (file_type == UPLOAD))
 		printf("inflight_size %d time  %f\n", (ts->snd_nxt - ack_seq), time - ts->start_time);
	ts->rwnd = ntohs(th->window) * ts->rwnd_scale;
	//printf("rwnd %d\n", ts->rwnd);
	ts->in_data_size = ts->in_data_size + len;

	ts->snd_una = ack_seq;
	ts->rcv_una = seq + len;

	if (IS_SYN(th) || IS_FIN(th))
		ts->rcv_una += 1;

	struct sack_block *cur_sack = &ts->option.sack;
	if (cur_sack->num != 0) {
		int l;
		uint32_t b, e;
		// find spurious retrans
		l = spurious_retrans(ts->snd_una, cur_sack, &b, &e);
		if (l != 0) 
			append_to_range_list(&ts->spurious_retrans_list, b, e);

		normalize(cur_sack);

		// Find reordering, no matter whether it's in recovery mode. We can
		// remove the real lost when finishing the flow.
		l = get_reordering(ts->snd_una, cur_sack, &b, &e);
		if (l != 0) 
			update_reordering(ts, b, e);

		add_to_block_list(cur_sack, &ts->block_list);
	}

	memcpy(&ts->sack, cur_sack, sizeof(struct sack_block));

	if (ts->ca_state == TCP_CA_RECOVERY) {
		if (ack_seq > ts->recovery_point || 
				(ack_seq == ts->recovery_point && cur_sack->num == 0)) {
			ts->recovery_point = 0;
			ts->ca_state = TCP_CA_OPEN;
		}
	}
	else {
		int rtt = get_rtt(ack_seq, time, &ts->rtt_list);
		if (rtt != 0){
			update_rtt(&ts->rtt, rtt);
			double srtt_temp = ts->rtt.srtt >> 3;
			append_to_range_list(&ts->srtt_list, srtt_temp, 0);
		}
	}
}

static void handle_out_pkt(struct tcp_state *ts, struct tcphdr *th, double time, int len)
{
	uint32_t seq = ntohl(th->seq),
			 ack_seq = ntohl(th->ack_seq);
	if (ts->seq_base == 0)
		ts->seq_base = seq;
	ts->pkt_out_cnt += 1;
	printf("seq %d time %f\n", seq - ts->seq_base, time - ts->start_time);
	if (seq < ts->snd_nxt) {
		ts->retrans_temp +=1;
		ts->ca_state = TCP_CA_RECOVERY;
		ts->recovery_point = ts->snd_nxt;
		if (len > 0)
			append_to_range_list(&ts->retrans_list, seq, seq+len);
	}
	else {
		// MAX can not distinguish number 7 and -9
		//ts->snd_nxt = MAX(seq+ len, ts->snd_nxt);
		ts->snd_nxt = seq+ len;
		ts->flow_size += len;
		if (IS_SYN(th) || IS_FIN(th))
			ts->snd_nxt += 1;

		// set tail flag
		if (ts->ca_state == TCP_CA_OPEN) {
			if (IS_SYN(th))
				ts->tail = 0;
			else if (IS_FIN(th))
			{
				ts->tail = 1;
			}
			else if (len>0 && len < ts->max_snd_seg_size && 
					ts->rwnd >= ts->max_snd_seg_size)
			{
				ts->tail = 1;
			}
			else
			{ 
				ts->tail = 0;
			}
		}
	}

	// update max_snd_seg_size
	ts->max_snd_seg_size = MAX(ts->max_snd_seg_size, len);
	//ts->max_snd_seg_size = 1448;
	// Set the time that this packet has being send out.	
	insert_seq_rtt(seq+len, time, &ts->send_out_time_list);

	ts->rcv_nxt = ack_seq;

	if (ts->ca_state == TCP_CA_RECOVERY) {
		if (seq < ts->recovery_point) {
			//if (len > 0)
			//	append_to_range_list(&ts->retrans_list, seq, seq+len);
		}
		else {
			ts->ca_state = TCP_CA_OPEN;
		}
	}
	else {
		uint32_t seq_una = seq + len;
		// we do not consider other flags like URG.
		if (IS_SYN(th) || IS_FIN(th))
			seq_una += 1;
		insert_seq_rtt(seq_una, time, &ts->rtt_list);
	}
	
}

int tcp_state_machine(struct tcp_state *ts, struct tcphdr *th, int len, double cap_time, int dir)
{
	uint32_t seq = ntohl(th->seq);
	uint32_t ack_seq = ntohl(th->ack_seq);
	
	// set head flags
	if ((dir == DIR_IN && IS_SYN(th))||(dir == DIR_IN && len>1))
		ts->head=1;

	//set the tail burst
	if((ts->last_pkt_dir == DIR_OUT)&&((cap_time-ts->last_time)<0.0005)&&(seq>=ts->snd_nxt))
		ts->tail_burst +=1;
	else
	{
		if(ts->tail_burst>=2)
			//printf("%d\n", ts->tail_burst);

		ts->tail_burst =0;
	}

	if (dir == DIR_IN && IS_SYN(th)) {
		// client may reestablish a connection
		ts->state = TCP_SYN_RECV;
	
		ts->start_time = cap_time;
		ts->last_time = cap_time;
		ts->last_stall_time = cap_time;
	}
	else if (IS_RST(th)) {
		// both can drop the connection by RST
		ts->state = TCP_CLOSING;
	}
	else {
		switch (ts->state) {
			case TCP_LISTEN:
				if (dir == DIR_IN && IS_SYN(th))
					ts->state = TCP_SYN_RECV;
				break;
			case TCP_SYN_RECV:
				if (dir == DIR_OUT && IS_SYN(th)) {
					ts->state = TCP_SYN_SENT;

					//ts->seq_base = seq;
					//printf("initial seq number is: %d\n", seq);
					ts->last_stall_point = ts->seq_base;
				}
				break;
			case TCP_SYN_SENT:
				if (dir == DIR_IN && IS_ACK(th)) {
					ts->state = TCP_ESTABLISHED;
				}
				break;
			case TCP_ESTABLISHED:
				if (IS_RST(th)) {
					ts->state = TCP_CLOSING;
				}
				else if (IS_FIN(th)) {
					if (dir == DIR_IN) 
						ts->state = TCP_FIN_WAIT1;
					else
						ts->state = TCP_FIN_WAIT2;
				}
				break;
			case TCP_FIN_WAIT1:
				if ((cap_time - ts->last_time)>5)
					ts->reset = 1;

				if (dir == DIR_OUT && ack_seq == ts->rcv_una)
					ts->state = TCP_CLOSE;
				break;
			case TCP_FIN_WAIT2:
				if ((cap_time - ts->last_time)>5)
					ts->reset = 1;
				if (dir == DIR_IN && ack_seq == ts->snd_nxt)
					ts->state = TCP_CLOSE;
				break;
			case TCP_CLOSING:
				// do nothing here, wait for the timeout
				break;
			default:
				LOG(ERROR, "unknown tcp state: %d.\n", ts->state);
				break;
		}
	}

	if (ts->state == TCP_CLOSING || ts->state == TCP_CLOSE)
		return 0;

	int thres = rtt_thres(&ts->rtt);
	//double thres = 0.000001;	
	// check whether there is a stall
	//double  duration = 0.0;
	int duration = 0;
	if (dir == DIR_IN && IS_SYN(th)) {
		ts->start_time = cap_time;
	}
	else {
		duration = TIME_TO_TICK(cap_time - ts->last_time);
		//duration = cap_time - ts->last_time;
	}
	if (duration > thres) {
		// store the (partial) stall state in list
		ts->stall_cnt += 1;
		//use get_rtt to get the real RTO of this packet
		int real_RTO;
		if (dir == DIR_OUT){
			real_RTO = get_rtt(seq+len, cap_time, &ts->send_out_time_list);
			if (real_RTO == 0)
				real_RTO = duration;
		}

		struct tcp_stall_state *tss = MALLOC(struct tcp_stall_state);
		init_tcp_stall(ts, tss, TICK_TO_TIME(duration),dir,len,seq, TICK_TO_TIME(real_RTO));
		list_insert(&tss->list, ts->stall_list.prev, &ts->stall_list);

		// finally, update the following info
		ts->last_stall_point = ts->snd_una;
		ts->last_stall_time = cap_time;
	}

	// parse tcp options
	get_tcp_option(th, &ts->option);

	if (dir == DIR_OUT) {
		handle_out_pkt(ts, th, cap_time, len);
	}
	else {
		handle_in_pkt(ts, th, cap_time, len);
	}

	/* use bytes as the metrics */
	ts->packets_out = ts->snd_nxt - ts->snd_una;
	ts->sacked_out = sacked(ts->snd_una, &ts->sack);
	if (ts->sacked_out > 0) 
		ts->holes = max_sack_ack(&ts->sack) - ts->snd_una - ts->sacked_out;
	else
		ts->holes = 0;

	if (ts->sack.num > 0) 
		ts->fackets_out = max_sack_ack(&ts->sack) - ts->snd_una;
	else 
		ts->fackets_out = 0;

	ts->retrans_out = list_range_size(&ts->retrans_list, ts->snd_una, ts->snd_nxt);
	ts->outstanding = ts->packets_out - ts->sacked_out + ts->retrans_out;

	if ((duration > thres)&&(ts->this_transfer_begin_time != 0)) {
		ts->total_duration +=TICK_TO_TIME(duration);
		if ((ts->state == TCP_ESTABLISHED) && (seq < (ts->snd_nxt-len)) &&(dir == DIR_OUT)) {
			ts->retrans_duration +=TICK_TO_TIME(duration);
		}
	}
	
	// set head flags
	if (dir == DIR_OUT && len >1)
		ts->head=0;
	if(dir == DIR_IN && len>1)
	{
		ts->file_num +=1;
		if( ts->this_transfer_begin_time != 0)	
			ts->total_transfer_time += ts->last_in_time - ts->this_transfer_begin_time;
		
		ts->this_transfer_begin_time = cap_time;
	}
	

	// after all processing
	ts->last_pkt_dir = dir;
	ts->last_time = cap_time;
	if (dir == DIR_IN) {
		ts->last_in_time = cap_time;
	}
	else {
		ts->last_out_time = cap_time;
	}

	return 0;
}

static inline void dump_list(FILE *fp, const char *fmt, \
		struct tcp_state *ts, struct list_head *list, int *num)
{
	struct list_head *p;
	//struct range_t *r;
	//fprintf(fp, fmt);
	list_for_each(p, list) {
		(*num) +=1;
		//r = list_entry(p, struct range_t, list);
		/*
		fprintf(fp, " (%d,%d,%d)", 
				(r->begin - ts->seq_base), 
				(r->end - ts->seq_base),
				DIV_CEIL(r->end - r->begin, ts->max_snd_seg_size));
	*/
	}
	//fprintf(fp, "\n");
}

static inline int dump_list_rtt(struct list_head *list)
{
	struct list_head *p;
	struct range_t *r;
	int num=0;
	int total_srtt=0, avg_srtt_temp=0;
	list_for_each(p, list) {
		num +=1;
		r = list_entry(p, struct range_t, list);
		total_srtt = total_srtt + r->begin;
	}
	if(num >= 1){
		avg_srtt_temp = total_srtt/num;
	}
	return avg_srtt_temp;
}

void dump_tss_list(FILE *fp, struct list_head *list)
{
	struct list_head *pos;
	struct tcp_stall_state *tss;
	list_for_each(pos, list) {
		tss = list_entry(pos, struct tcp_stall_state, list);
		enum stall_type type = parse_stall(tss);
		fprintf(fp, "%s: \"%s\" ", stall_text[type], stall_details[type]);
		dump_tss_info(fp, tss);
	}
}

void dump_ts_info(FILE *fp, struct tcp_state *ts)
{
	int retrans_num = 0, reorder_num = 0, spurious_num = 0, lost_num =0;
	double transfer_time;
	transfer_time = (ts->total_transfer_time + (ts->last_in_time - ts->this_transfer_begin_time));

	//calculate the reduce duration if use 2*RTT as RTO
	
	struct list_head *pos;
	struct tcp_stall_state *tss;
	struct list_head *list = &ts->stall_list;
	ts->retrans_duration =0;
	ts->pkt_delay_duration =0;
	list_for_each(pos, list) {
		tss = list_entry(pos, struct tcp_stall_state, list);
		if((tss->cur_pkt_spurious_num + tss->cur_pkt_lost_num) >= 1){
			//if ((tss->real_rto - 2*tss->srtt)>0){
				//ts->reduce_duration += tss->real_rto - 2*tss->srtt;
			//}
			//ts->retrans_duration += tss->real_rto;
		}
		if((tss->head != 1)&&(tss->cur_pkt_dir == 1)){
			//if ((tss->duration -2*tss->srtt)>0){
				ts->pkt_delay_duration += tss->duration -2*tss->srtt;
			//}
		}
	}

	//double avg_srtt =TICK_TO_TIME(dump_list_rtt(&ts->srtt_list));

	dump_list(fp, "retrans:", ts, &ts->retrans_list, &retrans_num);
	dump_list(fp, "reorder:", ts, &ts->reordering_list, &reorder_num);
	dump_list(fp, "spurious:", ts, &ts->spurious_retrans_list, &spurious_num);
	dump_list(fp, "lost:", ts, &ts->lost_list, &lost_num);
	//fprintf(fp, "lost_num %d ", lost_num);
	//fprintf(fp, "retrans_num %d ", retrans_num);
	//fprintf(fp, "retrans_temp: %d ", ts->retrans_temp);
	//fprintf(fp, "file_num: %d ", ts->file_num);
	//fprintf(fp, "flow_size %d ", ts->flow_size);
	//fprintf(fp, "file_transfer_time %f ", transfer_time);
	//fprintf(fp, "flow_rate %f ", ts->flow_size/transfer_time);
	//fprintf(fp, "ideal_reduce_time %f ", ts->reduce_duration + ts->pkt_delay_duration);
	if((transfer_time - ts->reduce_duration - ts->pkt_delay_duration)>0){
		//fprintf(fp, "ideal_rate %f ",ts->flow_size/(transfer_time - ts->reduce_duration - ts->pkt_delay_duration));
	}else{
		//fprintf(fp, "ideal_rate %f ",ts->flow_size/transfer_time);
	}
	//fprintf(fp, "flow_time: %f ", (ts->last_time - ts->start_time));
	//fprintf(fp, "total_duration: %f ", ts->total_duration);
	//fprintf(fp, "ideal_rate: %f ",ts->flow_size/(transfer_time - ts->total_duration));
	//fprintf(fp, "retrans_duration: %f ", ts->retrans_duration);
	//fprintf(fp, "rate_without_retrans: %f ",ts->flow_size/(transfer_time - ts->retrans_duration));
	//fprintf(fp, "reduce_duration: %f ",ts->reduce_duration);
	//fprintf(fp, "flow_time_reduce_duration: %f ",transfer_time - ts->reduce_duration);
	//fprintf(fp, "rate_reduce_duration: %f ",ts->flow_size/(transfer_time - ts->reduce_duration));
	//fprintf(fp, "reset %d ", ts->reset);
	//fprintf(fp, "avg_srtt %f \n", avg_srtt);
	double rate;
	if (file_type == DOWNLOAD)
	{
		if(ts->pkt_out_cnt > 0)
			rate = 1.0*ts->retrans_temp/ts->pkt_out_cnt;
		fprintf(fp,"download pkt_cnt: %d reorder_cnt: %d reorder_rate %f\n", ts->pkt_out_cnt, ts->retrans_temp, rate);
	}
	if (file_type == UPLOAD)
	{
		if(ts->pkt_out_cnt > 0)
			rate = 1.0*lost_num/ts->pkt_out_cnt;
		fprintf(fp,"upload pkt_cnt: %d loss_cnt: %d loss_rate %f\n", ts->pkt_out_cnt, lost_num, rate);
	}
}

static void free_tcp_state(struct tcp_state *ts)
{
	delete_rtt_list(&ts->rtt_list);

	delete_list(&ts->retrans_list, struct range_t, list);
	delete_list(&ts->block_list, struct range_t, list);
	delete_list(&ts->reordering_list, struct range_t, list);
	delete_list(&ts->spurious_retrans_list, struct range_t, list);
	delete_list(&ts->lost_list, struct range_t, list);
	delete_list(&ts->srtt_list, struct range_t, list);
	
	delete_list(&ts->stall_list, struct tcp_stall_state, list);

	FREE(ts);
}

void finish_tcp_state(struct tcp_state *ts)
{
	if (ts->max_snd_seg_size != 0) {
		get_lost_list(ts);
		get_reord_list(ts);

		fill_tcp_stall_list(ts, &ts->stall_list);
		FILE *fp = stdout;
		// exclude the up_stream
		//int flow_size = ts->snd_nxt - ts->seq_base;
		if (ts->in_data_size < 5000000){
		    //fprintf(fp, "name: %s\n", ts->name);
		    //fprintf(fp, "#(stalls): %d\n", ts->stall_cnt);
		    //fprintf(fp,"initial seq number is: %d\n", ts->seq_base);
		    dump_ts_info(fp, ts);
		    // dump tss info
		    //dump_tss_list(fp, &ts->stall_list);
		    //printf("%d\n", ts->init_rwnd);
		    //printf("flow_time %f\n", (ts->last_time - ts->start_time));
		}
	}

	free_tcp_state(ts);
}
