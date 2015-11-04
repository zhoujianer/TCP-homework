#include "rule_parser.h"


const char *stall_details[] = {
	"File begin stall.",
	"stall as the ack packet delay.",
	"Rwnd limited",
	"retrans, because the init_rwnd is small, just 4096.",
	"tail retrans.",
	"Tail stall as the server send fin.",
	"cwnd limited and init rwnd limited, last packet is in",
	"cwnd limited and init rwnd limited, last packet is out",
	"rwnd limited and init rwnd limited",
	"retrans, because last retrans packet delay",
	"retrans, because ack delay",
	"retrans, because series packets lost",
	"retrans, unknown",
	"resource constraint",
	"unknown issue"
};

const char *stall_text[] = {
	"DATA_UNAVAILABLE",
	"PACKET_DELAY",
	"ZERO_RWND",
	"RETRANS_INIT_RWND_LIMITED",
	"TAIL_RETRANS",
	"CLIENT_IDLE",
	"SMALL_RETRANS_CWND_LIMITED_IN",
	"SMALL_RETRANS_CWND_LIMITED_OUT",
	"SMALL_RETRANS_RWND_LIMITED",
	"RETRANS_DOUBLE",
	"RETRANS_ACK_DELAY",
	"RETRANS_SERIES_RETRANS",
	"RETRANS_UNKNOWN",
	"RESOURCE_CONSTRAINT",
	"UNKNOWN_ISSUE"
};

enum stall_type parse_stall(struct tcp_stall_state *tss)
{
	if ((tss->head == 1))
		return DATA_UNAVAILABLE;
	if ((tss->cur_pkt_dir == 1))
		return PACKET_DELAY;
	if ((tss->rwnd < tss->max_snd_seg_size))
		return ZERO_RWND;
	if (((((tss->init_rwnd <= 4096) && (tss->outstanding <= (3 * tss->max_snd_seg_size))) && (tss->cur_pkt_lost_num >= 1)) && (tss->cur_pkt_dir == 2)))
		return RETRANS_INIT_RWND_LIMITED;
	if (((((tss->cur_pkt_lost_num >= 1) && (tss->tail == 1)) && (tss->cur_pkt_dir == 2)) && ((tss->snd_nxt - tss->cur_pkt_seq) <= (3 * tss->max_snd_seg_size))))
		return TAIL_RETRANS;
	if ((((tss->cur_pkt_spurious_num + tss->cur_pkt_lost_num) == 0) && (tss->tail == 1)))
		return CLIENT_IDLE;
	if ((((((tss->cur_pkt_lost_num >= 1) && (tss->cur_pkt_dir == 2)) && (tss->outstanding <= (3 * tss->max_snd_seg_size))) && (tss->rwnd > (3 * tss->max_snd_seg_size))) && (tss->last_pkt_dir == 1)))
		return SMALL_RETRANS_CWND_LIMITED_IN;
	if ((((((tss->cur_pkt_lost_num >= 1) && (tss->cur_pkt_dir == 2)) && (tss->outstanding <= (3 * tss->max_snd_seg_size))) && (tss->rwnd > (3 * tss->max_snd_seg_size))) && (tss->last_pkt_dir == 2)))
		return SMALL_RETRANS_CWND_LIMITED_OUT;
	if (((((tss->cur_pkt_lost_num >= 1) && (tss->cur_pkt_dir == 2)) && (tss->outstanding <= (3 * tss->max_snd_seg_size))) && (tss->rwnd <= (3 * tss->max_snd_seg_size))))
		return SMALL_RETRANS_RWND_LIMITED;
	if ((((tss->cur_pkt_spurious_num + tss->cur_pkt_lost_num) >= 2) && (tss->cur_pkt_dir == 2)))
		return RETRANS_DOUBLE;
	if ((((tss->cur_pkt_spurious_num == 1) && (tss->cur_pkt_lost_num == 0)) && (tss->cur_pkt_dir == 2)))
		return RETRANS_ACK_DELAY;
	if (((((tss->lost * tss->max_snd_seg_size) == tss->outstanding) && (tss->cur_pkt_dir == 2)) && ((tss->cur_pkt_spurious_num + tss->cur_pkt_lost_num) >= 1)))
		return RETRANS_SERIES_RETRANS;
	if (((tss->cur_pkt_dir == 2) && ((tss->cur_pkt_spurious_num + tss->cur_pkt_lost_num) >= 1)))
		return RETRANS_UNKNOWN;
	if ((tss->cur_pkt_dir == 2))
		return RESOURCE_CONSTRAINT;

	return UNKNOWN_ISSUE;
}
