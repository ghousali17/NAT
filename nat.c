/*
 * nftest.c
 * - demo program of netfilter_queue
 * - Patrick P. C. Lee
 *
 * - To run it, you need to be in root
 */

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "checksum.h"
extern "C" {
#include <linux/netfilter.h> /* Defines verdicts (NF_ACCEPT, etc) */
#include <libnetfilter_queue/libnetfilter_queue.h>
}

#define MIN(a,b) (((a)<(b))?(a):(b))

pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct cbdata
{  //NAT parameters
	unsigned int ip;
	unsigned int subnet;
	unsigned int mask;
	struct nat **nat;  //NAT table head
	
	//user space buffer for storing packets
	unsigned char pkt[10][4096]; //buffer space of 10 packets,each of maximum 4096 bytes
	unsigned short pkt_len[10];  
	unsigned int id[10];
    
	//head and tail for circular queue implementation on the user space buffer
	unsigned short head;
	unsigned short tail;

	//the number of packets in user space buffers.
	unsigned short count;

} cbdata;

typedef struct nat
{   
	unsigned int src_ip;
	unsigned int translated_ip;
	unsigned short src_port;
	unsigned short nat_port;
	unsigned int internal_flag_ack;
	unsigned int external_flag_ack;
	unsigned char internal_fin;
	unsigned char external_fin;
	// even if fin initiate by internal and odd if initiated by external
	struct nat *next;
} nat;

typedef struct verdict_t_args //arguments for verdict thread
{
	nfq_q_handle *myQueue;
	struct cbdata *cbData;
	int bucket_size;
	int fill_rate;
}verdict_t_args;


void print_ip(unsigned int ip);
int verify_subnet(unsigned int lan_ip, unsigned int src_ip, int mask);

struct nat *insert_nat(unsigned int src_ip, unsigned short src_port, unsigned int translated_ip, struct nat **head);
struct nat *return_nat(unsigned int src_ip, unsigned short src_port, struct nat *head);
struct nat *return_nat(unsigned short nat_port, struct nat *head);
void remove_nat(unsigned int nat_port, struct nat **head);
void print_nat(struct nat *nat);

void *receive_thread(void *args);
void *verdict_thread(void *argument);

/*
 * Callback function installed to netfilter queue
 */
static int Callback(nfq_q_handle *myQueue, struct nfgenmsg *msg,
					nfq_data *pkt, void *callback_argument) {

	struct cbdata *cb_data = (struct cbdata *)callback_argument;
	unsigned char *pktData;
	unsigned int id = 0, tail;
	int i;
	
	nfqnl_msg_packet_hdr *header;

	int len = nfq_get_payload(pkt, (unsigned char **)&pktData);

	if ((header = nfq_get_msg_packet_hdr(pkt)))
		id = ntohl(header->packet_id);

	pthread_mutex_lock(&count_lock);
	 
	if (cb_data->count >= 10)
		nfq_set_verdict(myQueue, id, NF_DROP, len, pktData); //drop if no space in buffer
	else {   
		cb_data->count++;
		tail = cb_data->tail;
		for (i = 0; i < len; i++)
			cb_data->pkt[tail][i] = pktData[i];

		cb_data->pkt_len[tail] = len;
		cb_data->id[tail] = id;
		cb_data->tail = (tail+1)%10;
	}

    pthread_mutex_unlock(&count_lock);
    return id;
}


void *verdict_thread(void *argument)
{

	struct verdict_t_args *args = (struct verdict_t_args *)argument;
	struct cbdata *cb_data = args->cbData;
	nfq_q_handle *myQueue = args->myQueue;
	struct ip *ip_hdr;
	struct tcphdr *tcp_hdr;

	struct nat *target_nat; // the nat to route packet to or from
	unsigned int nat = cb_data->ip;
	unsigned int subnet = cb_data->subnet;
	unsigned int mask = cb_data->mask;
	unsigned int head;
	unsigned int src_ip;
	unsigned short src_port;
	unsigned short des_port;

	int bucket_size = args->bucket_size;
	int fill_rate = args->fill_rate;
	int tokens;
	struct timeval tokent1, tokent2;
	double time = 0;
	int bucket = bucket_size;
	gettimeofday(&tokent1, NULL);

	//iteratable begins!!
	while (1) 
	{   
		pthread_mutex_lock(&count_lock);
		if (cb_data->count <= 0)
		{
			pthread_mutex_unlock(&count_lock);
			continue;
		}
     	pthread_mutex_unlock(&count_lock);

		head = cb_data->head;
		cb_data->head = (head+1)%10;
		
		unsigned int id = cb_data->id[head];
		int len = cb_data->pkt_len[head];
		unsigned char *pktData = (unsigned char *)malloc(sizeof(unsigned char) * len);

		int i;
		for (i = 0; i < len; i++)
			pktData[i] = cb_data->pkt[head][i];

		ip_hdr = (struct ip *)pktData;
		if (ip_hdr->ip_p == IPPROTO_TCP) //check if packet is TCP
		{
			tcp_hdr = (struct tcphdr *)((unsigned char *)ip_hdr + (ip_hdr->ip_hl << 2));

			//disect packet header for printable iformation
			src_ip = ip_hdr->ip_src.s_addr;
			src_port = ntohs(tcp_hdr->source);
			des_port = ntohs(tcp_hdr->dest);

			if (verify_subnet(subnet, src_ip, mask) == 1) //compares the src_ip with subnet mask to
			{											  //determine if packet originated in subnet
				if ((target_nat = return_nat(src_ip, src_port, *(cb_data->nat))) == NULL) //nat doesn't exist
				{
					if (tcp_hdr->th_flags & TH_SYN) //create new connection for outbound packet only if SYN is set.
					{
						target_nat = insert_nat(src_ip, src_port, nat, cb_data->nat);
						if (target_nat == NULL) {
							pthread_mutex_lock(&count_lock);
							cb_data->count--;
							pthread_mutex_unlock(&count_lock);

							nfq_set_verdict(myQueue, id, NF_DROP, len, pktData);
							continue;
						}
						print_nat(*(cb_data->nat));
					}
					else
					{
						//drop unmapped packets with no SYN flags.
						pthread_mutex_lock(&count_lock);
						cb_data->count--;
						pthread_mutex_unlock(&count_lock);

						nfq_set_verdict(myQueue, id, NF_DROP, len, pktData);
						continue;
					}
				}

				//modify outgoing packets and computer checksums
				ip_hdr->ip_src.s_addr = cb_data->ip; 
				tcp_hdr->source = htons(target_nat->nat_port);
				ip_hdr->ip_sum = ip_checksum((unsigned char *)ip_hdr); //order of checksum calculation important
				tcp_hdr->check = tcp_checksum((unsigned char *)ip_hdr);

				if (tcp_hdr->th_flags & TH_FIN) //checks if outgoing packet has the FIN flag set
					target_nat->internal_flag_ack = ntohl(tcp_hdr->seq) + 1; //if FIN flag set set the expected ACK number.

				if (target_nat->external_flag_ack != 0 && target_nat->external_flag_ack == ntohl(tcp_hdr->ack_seq)) 
				{	//checks if out going packet is an ACK for FIN
					target_nat->external_fin = '1';
					if (target_nat->internal_fin == '1') // checks if both FINs have been acked.
					{
						remove_nat(target_nat->nat_port, cb_data->nat);
						print_nat(*(cb_data->nat));
					} //removed NAT entry if both FINs have been acked.
				}
				if (tcp_hdr->th_flags & TH_RST) //checks if reset flag has been set.
				{
					target_nat = return_nat(src_ip, src_port, *(cb_data->nat)); //returns the NAT for the connection to be reset
					if (target_nat != NULL)
					{
						remove_nat(target_nat->nat_port, cb_data->nat);
						print_nat(*(cb_data->nat));
					}
				}
			}
			else
			{
				if ((target_nat = return_nat(des_port, *(cb_data->nat))) == NULL) //checks if NAT mapping exists for incoming packet
				{
					pthread_mutex_lock(&count_lock);
					cb_data->count--;
					pthread_mutex_unlock(&count_lock);

					nfq_set_verdict(myQueue, id, NF_DROP, len, pktData);
					continue;
				}

				//modify incoming packets and modify checksums
				ip_hdr->ip_dst.s_addr = target_nat->src_ip;
				tcp_hdr->dest = htons(target_nat->src_port);
				ip_hdr->ip_sum = ip_checksum((unsigned char *)ip_hdr); //order of checksum calculation important
				tcp_hdr->check = tcp_checksum((unsigned char *)ip_hdr);

				if (tcp_hdr->th_flags & TH_FIN) //checks if incoming packet has the FIN flag set
					target_nat->external_flag_ack = ntohl(tcp_hdr->seq) + 1; //set the acknowledgement number for the FIN

				if (target_nat->internal_flag_ack != 0 && target_nat->internal_flag_ack == ntohl(tcp_hdr->ack_seq)) //checks if the incoming packet is the ACK for a FIN
				{
					target_nat->internal_fin = '1';
					if (target_nat->external_fin == '1') //checks if ACKs for both FIN have been received.
					{
						remove_nat(target_nat->nat_port, cb_data->nat);
						print_nat(*(cb_data->nat));
					} //remove NAT if both FINs received.
				}
				if (tcp_hdr->th_flags & TH_RST) //checks if reset flag has been set.
				{
					target_nat = return_nat(ip_hdr->ip_dst.s_addr, ntohs(tcp_hdr->dest), *(cb_data->nat)); //returns the NAT for the connection to be reset
					if (target_nat != NULL)
					{
						remove_nat(target_nat->nat_port, cb_data->nat);
						print_nat(*(cb_data->nat));
					}
				}
			}

			pthread_mutex_lock(&count_lock);
			cb_data->count--;
			pthread_mutex_unlock(&count_lock);

			// Token Bucket
			int delivered = 0;
			struct timespec t1, t2;
			t1.tv_sec = 0;
			t1.tv_nsec = 5000;

			while (delivered == 0) {

				if (bucket > 0) {	// If bucket has tokens
					bucket--;
					nfq_set_verdict(myQueue, id, NF_ACCEPT, len, pktData);
					delivered = 1;	// Exit while loop
				}
				else {	// If no tokens, sleep for 5 us and then recheck for tokens
					if (nanosleep(&t1, &t2) < 0) {
						printf("ERROR: nanosleep() system call failed.\n");
						exit(1);
					}
					gettimeofday(&tokent2 ,NULL);
					time = (double)(tokent2.tv_sec - tokent1.tv_sec) + (tokent2.tv_usec - tokent1.tv_usec)/1000000.0;
					gettimeofday(&tokent1, NULL);
					tokens = bucket + time * fill_rate;
					bucket = MIN(bucket_size, tokens);
				}
			}
			continue;	// Move to the next packet
		}
		// If not a TCP packet
		pthread_mutex_lock(&count_lock);
		cb_data->count--;
		pthread_mutex_unlock(&count_lock);
		nfq_set_verdict(myQueue, id, NF_DROP, len, pktData);
		
	}
	pthread_exit(NULL);
}

void print_ip(unsigned int ip)
{
	char ip_address[16];
	int len;
	int padding;
	int i;
	sprintf(ip_address, "%u.%u.%u.%u", ip & 0xff, (ip >> 8) & 0xff,
			(ip >> 16) & 0xff, (ip >> 24) & 0xff);
	len = strlen(ip_address);
	padding = 15 - len;

	for (i = 0; i < padding; i++)
		strcat(ip_address, " ");

	printf("%s", ip_address);
}

void print_nat(struct nat *nat)
{
	struct nat *temp = nat;
	printf("\nNAT:\n");
	printf("-----------------------------------------------------------\n");
	printf("|     LAN IP     | LAN PORT  |     NAT IP     | NAT PORT  |\n");
	printf("-----------------------------------------------------------\n");

	while (temp != NULL)
	{
		printf("| ");
		print_ip(temp->src_ip);
		printf("|   %05u   |", temp->src_port);
		printf(" ");
		print_ip(temp->translated_ip);
		printf("|   %05u   |\n", temp->nat_port);
		temp = temp->next;
	}
	printf("-----------------------------------------------------------\n");
}

// determine if the packet is outbound or inbound
int verify_subnet(unsigned int lan_ip, unsigned int src_ip, int mask) {

	unsigned int local_mask = 0xffffffff << (32 - mask);
	if ((ntohl(lan_ip) & local_mask) == (ntohl(src_ip) & local_mask))
		return 1;
	else
		return 0;
}

struct nat *insert_nat(unsigned int src_ip, unsigned short src_port, unsigned int translated_ip, struct nat **head)
{
	struct nat *new_node = (struct nat *)malloc(sizeof(nat));
	new_node->src_ip = src_ip;
	new_node->translated_ip = translated_ip;
	new_node->src_port = src_port;
	new_node->next = NULL;
	new_node->external_flag_ack = 0;
	new_node->internal_flag_ack = 0;
	new_node->internal_fin = '0';
	new_node->external_fin = '0';

	if (*head == NULL)
	{
		new_node->nat_port = 10000;
		*head = new_node;
	}
	else
	{
		if ((*head)->nat_port > 10000) // if insertion at head required
		{
			new_node->nat_port = 10000;
			new_node->next = *head;
			*head = new_node;
			return new_node;
		}

		struct nat *cur = *head;
		struct nat *pre = NULL;
		while (cur != NULL)
		{
			if (pre != NULL)
			{
				if ((cur->nat_port - pre->nat_port) > 1)
					break;
			}
			pre = cur;
			cur = cur->next;
		}
		if (pre->nat_port < 12000) {
			new_node->nat_port = pre->nat_port + 1;
			new_node->next = cur;
			pre->next = new_node;
		} else {
			return NULL;
		}
	}
	return new_node;
}

struct nat *return_nat(unsigned int src_ip, unsigned short src_port, struct nat *head)
{
	struct nat *temp = head;
	while (temp != NULL)
	{
		if (temp->src_ip == src_ip && temp->src_port == src_port)
			return temp;
		temp = temp->next;
	}

	return NULL;
}

struct nat *return_nat(unsigned short nat_port, struct nat *head)
{
	struct nat *temp = head;
	while (temp != NULL)
	{
		if (temp->nat_port == nat_port)
			return temp;
		temp = temp->next;
	}

	return NULL;
}

void remove_nat(unsigned int nat_port, struct nat **head)
{
	if ((*head)->nat_port == nat_port)
		*head = ((*head)->next);
	else
	{
		struct nat *cur = *head;
		struct nat *pre = NULL;
		while (cur != NULL)
		{
			if (cur->nat_port == nat_port)
				break;
			pre = cur;
			cur = cur->next;
		}
		pre->next = cur->next;
		free(cur);
	}
}

/*
 * Main program
 */
int main(int argc, char **argv)
{

	pthread_t tid;
	struct verdict_t_args thread_argument;
	struct nfq_handle *nfqHandle;
	struct cbdata cb_data;
	struct nfq_q_handle *myQueue;
	struct nfnl_handle *netlinkHandle;

	int fd, res;
	char buf[4096];

	if (argc != 6)
	{
		fprintf(stderr, "Usage: ./nat <IP> <LAN> <MASK> <bucket size> <fill rate>\n");
		exit(-1);
	}

	printf("[Press Ctrl-C to exit]\n");

	cb_data.ip = inet_addr(argv[1]);
	cb_data.subnet = inet_addr(argv[2]);
	cb_data.mask = (unsigned int)atoi(argv[3]);
	
	thread_argument.bucket_size = atoi(argv[4]);
	thread_argument.fill_rate = atoi(argv[5]);

	cb_data.nat = (struct nat **)malloc(sizeof(struct nat *));
	cb_data.head = 0;
	cb_data.tail = 0;
	cb_data.count = 0;
	*(cb_data.nat) = NULL;

	// Get a queue connection handle from the module
	if (!(nfqHandle = nfq_open()))
	{
		fprintf(stderr, "Error in nfq_open()\n");
		exit(-1);
	}

	// Unbind the handler from processing any IP packets
	// (seems to be a must)
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0)
	{
		fprintf(stderr, "Error in nfq_unbind_pf()\n");
		exit(1);
	}

	// Bind this handler to process IP packets...
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0)
	{
		fprintf(stderr, "Error in nfq_bind_pf()\n");
		exit(1);
	}

	// Install a callback on queue 0
	if (!(myQueue = nfq_create_queue(nfqHandle, 0, &Callback, &cb_data)))
	{
		fprintf(stderr, "Error in nfq_create_queue()\n");
		exit(1);
	}

	// Turn on packet copy mode
	if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "Could not set packet copy mode\n");
		exit(1);
	}

	netlinkHandle = nfq_nfnlh(nfqHandle);
	fd = nfnl_fd(netlinkHandle);
	
	thread_argument.myQueue = myQueue;
	thread_argument.cbData = &cb_data;

	pthread_create(&tid, NULL, verdict_thread, (void *)&thread_argument);

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0)
	{
		// I am not totally sure why a callback mechanism is used
		// rather than just handling it directly here, but that
		// seems to be the convention...

		nfq_handle_packet(nfqHandle, buf, res);

	}
	pthread_join(tid, NULL);
	nfq_destroy_queue(myQueue);

	nfq_close(nfqHandle);

	return 0;

	// end main
}
