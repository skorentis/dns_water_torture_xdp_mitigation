#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define MAX_DNS_NAME_LENGTH	60
#define MAX_LABEL_LENGTH 30
//#define DEBUG	ON

struct dnshdr{
    __u16 transaction_id;
    __u8 rd : 1;      //Recursion desired
    __u8 tc : 1;      //Truncated
    __u8 aa : 1;      //Authoritive answer
    __u8 opcode : 4;  //Opcode
    __u8 qr : 1;      //Query/response flag
    __u8 rcode : 4;   //Response code
    __u8 cd : 1;      //Checking disabled
    __u8 ad : 1;      //Authenticated data
    __u8 z : 1;       //Z reserved bit
    __u8 ra : 1;      //Recursion available
    __u16 q_count;    //Number of questions
    __u16 ans_count;  //Number of answer RRs
    __u16 auth_count; //Number of authority RRs
    __u16 add_count;  //Number of resource RRs
};

struct dns_query {
    char name[MAX_DNS_NAME_LENGTH];
    __u16 record_type;
    __u16 class;
};

// BPF_HASH(digits, __u8, __u8);
// BPF_HASH(vowels, __u8, __u8);
BPF_HASH(consonants, __u8, __u8);

BPF_HASH(valid_feature1, __u32, __u64);
BPF_HASH(valid_feature2, __u32, __u64);
BPF_HASH(valid_feature3, __u32, __u64);
BPF_HASH(valid_feature4, __u32, __u64);
BPF_HASH(valid_feature5, __u32, __u64);
BPF_HASH(valid_feature6, __u32, __u64);
BPF_HASH(valid_feature7, __u32, __u64);

BPF_HASH(invalid_feature1, __u32, __u64);
BPF_HASH(invalid_feature2, __u32, __u64);
BPF_HASH(invalid_feature3, __u32, __u64);
BPF_HASH(invalid_feature4, __u32, __u64);
BPF_HASH(invalid_feature5, __u32, __u64);
BPF_HASH(invalid_feature6, __u32, __u64);
BPF_HASH(invalid_feature7, __u32, __u64);

static int __always_inline parse_query(struct xdp_md *ctx, void *query_start, struct dns_query *q){
    void *data_end = (void *)(long)ctx->data_end;

    #ifdef DEBUG
    bpf_trace_printk("Parsing query\n");
    #endif

    __u16 i;
    void *cursor = query_start;
    int namepos = 0;

    //initialize name, record_type, class with zero bytes
	//for the verifier
    memset(&q->name[0], 0, sizeof(q->name));
    q->record_type = 0;
    q->class = 0;

    //bounded loop of MAX_DNS_NAME_LENGTH (maximum allowed dns name size).
	#pragma clang loop unroll(full)
    for (i = 0; i < MAX_DNS_NAME_LENGTH; i++){
        if (cursor + 1 > data_end){
            return XDP_ABORTED;
        }
        if (*(char *)(cursor) == 0){
            if (cursor + 5 > data_end){
				return XDP_ABORTED;
            }
            else{
                //q->record_type = bpf_htons(*(__u16 *)(cursor + 1));
                //q->class = bpf_htons(*(__u16 *)(cursor + 3));
				q->name[namepos] = '\0';
            }
            return namepos + 1 + 2 + 2;
        }
		q->name[namepos] = *(char *)(cursor);
		namepos += 1;
		cursor += 1;
    }
    return -1;
}

static int __always_inline naive_bayes_resolution(struct dns_query *query){
	
	__u32 total_length = (__u32)query->name[0];
	__u32 total_digits = 0;
	__u32 max_numeric_sequence = 0;
	__u32 tmp_numeric_sequence = 0;
	__u32 max_consonants_sequence = 0;
	__u32 tmp_consonants_sequence = 0;	
	__u32 max_vowels_sequence = 0;
	__u32 tmp_vowels_sequence = 0;
	__u32 total_vowels = 0;
	__u32 total_consonants = 0;
	__u16 i;
	__u8 c;
	__uint128_t valid_prob;
	__uint128_t invalid_prob;
	#pragma clang loop unroll(full)
	for (i = 1; i < MAX_LABEL_LENGTH; i++){
		if(i <= total_length){
			c = query->name[i];
			if(c >= 0x30 && c <= 0x39){
				tmp_consonants_sequence = 0;
				tmp_vowels_sequence = 0;
				total_digits++;
				tmp_numeric_sequence++;
				if(tmp_numeric_sequence > max_numeric_sequence)
					max_numeric_sequence = tmp_numeric_sequence;
				//bpf_trace_printk("found number : %u\n", c);
				}
			else if(c == 0x41 || c == 0x45 || c == 0x49 || c == 0x4f || c == 0x55 || c == 0x61 || c == 0x65 ||
					c == 0x69 || c == 0x6f || c == 0x75){
				tmp_numeric_sequence = 0;
				tmp_consonants_sequence = 0;
				total_vowels++;
				tmp_vowels_sequence++;
				if(tmp_vowels_sequence > max_vowels_sequence)
					max_vowels_sequence = tmp_vowels_sequence;
				//bpf_trace_printk("vowel ... %u\n", c);
				}
			else if(consonants.lookup(&c)){ 
				tmp_numeric_sequence = 0;
				tmp_vowels_sequence = 0;
				total_consonants++;
				tmp_consonants_sequence++;
				if(tmp_consonants_sequence > max_consonants_sequence)
					max_consonants_sequence = tmp_consonants_sequence;
				//bpf_trace_printk("CONSONANT %u\n", c);
				}
			else{
				tmp_numeric_sequence = 0;
				tmp_consonants_sequence = 0;
				tmp_vowels_sequence = 0;	
				continue;
			}
		}
	}

	__u64 *total_length_valid = valid_feature1.lookup(&total_length);
	__u64 *total_length_invalid = invalid_feature1.lookup(&total_length);

	__u64 *total_digits_valid = valid_feature2.lookup(&total_digits);
	__u64 *total_digits_invalid = invalid_feature2.lookup(&total_digits);

	__u64 *max_numeric_sequence_valid = valid_feature3.lookup(&max_numeric_sequence);
	__u64 *max_numeric_sequence_invalid = invalid_feature3.lookup(&max_numeric_sequence);

	__u64 *total_consonants_valid = valid_feature4.lookup(&total_consonants);
	__u64 *total_consonants_invalid = invalid_feature4.lookup(&total_consonants);

	__u64 *max_consonants_sequence_valid = valid_feature5.lookup(&max_consonants_sequence);
	__u64 *max_consonants_sequence_invalid = invalid_feature5.lookup(&max_consonants_sequence);

	__u64 *total_vowels_valid = valid_feature6.lookup(&total_vowels);
	__u64 *total_vowels_invalid = invalid_feature6.lookup(&total_vowels);

	__u64 *max_vowels_sequence_valid = valid_feature7.lookup(&max_vowels_sequence);
	__u64 *max_vowels_sequence_invalid = invalid_feature7.lookup(&max_vowels_sequence);

	//NULL pointer check
	if(total_length_valid && total_digits_valid && total_vowels_valid && total_consonants_valid && 
	max_numeric_sequence_valid && max_consonants_sequence_valid && max_vowels_sequence_valid){
		valid_prob = *total_length_valid * *total_digits_valid * *total_vowels_valid *
		 *total_consonants_valid * *max_numeric_sequence_valid * *max_consonants_sequence_valid * *max_vowels_sequence_valid;
	}
	else
		valid_prob = 0;

	if(total_length_invalid && total_digits_invalid && total_vowels_invalid && total_consonants_invalid && 
	max_numeric_sequence_invalid && max_consonants_sequence_invalid && max_vowels_sequence_invalid){
		invalid_prob = *total_length_invalid * *total_digits_invalid * *total_vowels_invalid *
		 *total_consonants_invalid * *max_numeric_sequence_invalid * *max_consonants_sequence_invalid * *max_vowels_sequence_invalid;
	}
	else
		invalid_prob = 0;
	
	//bpf_trace_printk("valid prob: %llu\n", valid_prob);
	//bpf_trace_printk("invalid prob: %llu\n", invalid_prob);
	if (valid_prob > invalid_prob){
		//bpf_trace_printk("NB result: YES\n");
		return XDP_PASS;
	}
	else{
		//bpf_trace_printk("NB result: NO\n");
		return XDP_DROP;
	}
}

int xdp_nb(struct xdp_md *ctx){
	//bpf_trace_printk("A packet entered the XDP filter ...\n");

	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	void *cursor = data;

	// boundary check ETH
	if (cursor + sizeof(struct ethhdr) > data_end) {
		#ifdef DEBUG
		bpf_trace_printk("ABORTED ETH\n");
		#endif
		return XDP_ABORTED;
	}
	cursor += sizeof(struct ethhdr);
	
	//boundary check IPv4
	if (cursor + sizeof(struct iphdr) > data_end) {
		#ifdef DEBUG
		bpf_trace_printk("ABORTED IP\n");
		#endif
		return XDP_ABORTED;
	}
	cursor += sizeof(struct iphdr);

	//boundary check UDP
	if (cursor + sizeof(struct udphdr) > data_end) {
		#ifdef DEBUG
		bpf_trace_printk("ABORTED UDP\n");
		#endif
		return XDP_ABORTED;
	}

	//check if port 53
	struct udphdr *udp_header = cursor;
	if (bpf_ntohs(udp_header->dest) != 53){
		#ifdef DEBUG
		bpf_trace_printk("non dns related udp packet passed...\n");
		#endif
		return XDP_PASS;
	}
	cursor += sizeof(struct udphdr);
	
	//boundary check DNS
	if (cursor + sizeof(struct dnshdr) > data_end) {
		#ifdef DEBUG
		bpf_trace_printk("ABORTED DNS\n");
		#endif
		return XDP_ABORTED;
	}
	//check if DNS packet is a response or a query
	struct dnshdr *dns_header = cursor;
	if (dns_header->qr != 0){
		#ifdef DEBUG
		bpf_trace_printk("a dns response packet passed...\n");
		#endif
		return XDP_PASS;
	}
	cursor += sizeof(struct dnshdr);


	//parsing a single query for now
	struct dns_query query;
	int query_length = 0;
	query_length = parse_query(ctx, cursor, &query);
	bpf_trace_printk("dns query name: %s\n",query.name);
	if (query_length < 1){
		#ifdef DEBUG
		bpf_trace_printk("ABORTED DNS query\n");
		#endif
		return XDP_PASS;
	}

	if((int)query.name[0] > MAX_LABEL_LENGTH)
		return XDP_DROP;
	
	return naive_bayes_resolution(&query);
}

int xdp_test(struct xdp_md *ctx){	
	//bpf_trace_printk("A packet entered the XDP filter ...\n");
	return XDP_DROP;
}