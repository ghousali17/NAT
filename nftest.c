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
#include <time.h>
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
typedef struct cbdata
{
	unsigned int ip;
	unsigned int subnet;
	unsigned int mask;
	struct nat **nat;
} cbdata;

typedef struct nat
{
	unsigned int src_ip;
	unsigned int translated_ip;
	unsigned short src_port;
	unsigned short nat_port;
	struct nat *next;
	unsigned int internal_flag_ack;
	unsigned int external_flag_ack;
	unsigned char internal_fin;
	unsigned char external_fin;
	// even if fin initiate by internal and odd if initiated by external
} nat;

void print_ip(unsigned int ip);
void print_nat(struct nat *nat);
int verify_subnet(unsigned int lan_ip, unsigned int src_ip, int mask);
struct nat *insert_nat(unsigned int src_ip, unsigned short src_port, unsigned int translated_ip, struct nat **head);
struct nat *return_nat(unsigned int src_ip, unsigned short src_port, struct nat *head);
struct nat *return_nat(unsigned short nat_port, struct nat *head);
void remove_nat(unsigned int nat_port, struct nat **head);
void *receive_thread(void *args);
pthread_mutex_t recv_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * Callback function installed to netfilter queue
 */
static int Callback(nfq_q_handle *myQueue, struct nfgenmsg *msg,
					nfq_data *pkt, void *cbData)
{
	unsigned int id = 0;
	nfqnl_msg_packet_hdr *header;
	struct ip *ip_hdr;
	struct tcphdr *tcp_hdr;
	struct cbdata *cb_data = (struct cbdata *)cbData;
	struct nat *target_nat; // the nat to route packet to or from
	unsigned int nat = cb_data->ip;
	unsigned int subnet = cb_data->subnet;
	unsigned int mask = cb_data->mask;

	unsigned int src_ip;
	unsigned int des_ip;
	unsigned short src_port;
	unsigned short des_port;
	unsigned short nat_port;
	if ((header = nfq_get_msg_packet_hdr(pkt)))
	{
		id = ntohl(header->packet_id);
		//printf("  id: %u\n", id);
	}

	// print the timestamp (PC: seems the timestamp is not always set)

	// Print the payload; in copy meta mode, only headers will be
	// included; in copy packet mode, whole packet will be returned.
	//printf(" payload: ");
	unsigned char *pktData;
	int len = nfq_get_payload(pkt, (unsigned char **)&pktData);
	ip_hdr = (struct ip *)pktData;

	if (ip_hdr->ip_p == IPPROTO_TCP) //check if packet is TCP
	{
		tcp_hdr = (struct tcphdr *)((unsigned char *)ip_hdr + (ip_hdr->ip_hl << 2));

		//disect packet heafer for printable iformation
		src_ip = ip_hdr->ip_src.s_addr;
		des_ip = ip_hdr->ip_dst.s_addr;
		src_port = ntohs(tcp_hdr->source);
		des_port = ntohs(tcp_hdr->dest);

		//print tcp packet details
		printf("  ");
		print_ip(src_ip);
		printf(" :%u -> ", src_port);
		printf(" ");
		print_ip(des_ip);
		printf(" :%u\n", des_port);

		if (verify_subnet(subnet, src_ip, mask) == 1) //compares the src_ip with subnet mask to
		{											  //determine if packet originated in subnet
			printf("  outbound\n");

			if ((target_nat = return_nat(src_ip, src_port, *(cb_data->nat))) == NULL)
			{
				if (tcp_hdr->th_flags & TH_SYN) //create new connection for outbound packet only if SYN is set.
				{
					printf("  creating nat entry\n");
					target_nat = insert_nat(src_ip, src_port, nat, cb_data->nat);
				}
				else
				{
					printf("  unrecognized packet:dropping\n"); //drop unmapped packets with no SYN flags.
					return nfq_set_verdict(myQueue, id, NF_DROP, len, pktData);
				}
			}
			else
			{
				printf("  routing to %u\n", target_nat->nat_port); //if mapping exists forward packet after modification
			}
			//modify outgoing packets and computer checksums
			ip_hdr->ip_src.s_addr = cb_data->ip; //remove 1
			tcp_hdr->source = htons(target_nat->nat_port);
			ip_hdr->ip_sum = ip_checksum((unsigned char *)ip_hdr); //order of checksum calculation important
			tcp_hdr->check = tcp_checksum((unsigned char *)ip_hdr);

			if (tcp_hdr->th_flags & TH_FIN) //checks if outgoing packet has the FIN flag set
			{
				target_nat->internal_flag_ack = ntohl(tcp_hdr->seq) + 1; //if FIN flag set set the expected ACK number.
			}

			if (target_nat->external_flag_ack != 0 && target_nat->external_flag_ack == ntohl(tcp_hdr->ack_seq)) //checks if out going packet is an ACK for FIN
			{
				printf("  received ack for externally generated fin:%u!\n", ntohl(tcp_hdr->ack_seq));

				target_nat->external_fin = '1';
				if (target_nat->internal_fin == '1')				// checks if both FINs have been acked.
					remove_nat(target_nat->nat_port, cb_data->nat); //removed NAT entry if both FINs have been acked.
			}
		}
		else
		{
			printf("  inbound\n");
			if ((target_nat = return_nat(des_port, *(cb_data->nat))) == NULL) //checks if NAT mapping exists for incoming packet
			{
				printf("  inbound nat entry doesnt exist\n"); // drop packet if mapping doesnt exist.
				return nfq_set_verdict(myQueue, id, NF_DROP, len, pktData);
			}
			else
			{
				printf("  routing to host:");
				print_ip(target_nat->src_ip);
				printf(" :%u\n", target_nat->src_port);

				//modify incoming packets and modify checksums
				ip_hdr->ip_dst.s_addr = target_nat->src_ip;
				tcp_hdr->dest = htons(target_nat->src_port);
				ip_hdr->ip_sum = ip_checksum((unsigned char *)ip_hdr); //order of checksum calculation important
				tcp_hdr->check = tcp_checksum((unsigned char *)ip_hdr);

				if (tcp_hdr->th_flags & TH_FIN) //checks if incoming packet has the FIN flag set
				{
					target_nat->external_flag_ack = ntohl(tcp_hdr->seq) + 1; //set the acknowledgement number for the FIN
				}
				if (target_nat->internal_flag_ack != 0 && target_nat->internal_flag_ack == ntohl(tcp_hdr->ack_seq)) //checks if the incoming packet is the ACK for a FIN
				{
					printf("  received ack for internally genrated fin:%u!\n", ntohl(tcp_hdr->ack_seq));

					target_nat->internal_fin = '1';
					if (target_nat->external_fin == '1')				//checks if ACKs for both FIN have been received.
						remove_nat(target_nat->nat_port, cb_data->nat); //remove NAT if both FINs received.
				}
			}
		}

		if (tcp_hdr->th_flags & TH_RST) //checks if reset flag has been set.
		{
			target_nat = return_nat(src_ip, src_port, *(cb_data->nat)); //returns the NAT for the connection to be reset
			if (target_nat != NULL)
			{
				printf("  rst flag received!\n");
				remove_nat(target_nat->nat_port, cb_data->nat);
			}
		}
		print_nat(*(cb_data->nat));
		printf("\n");
		return nfq_set_verdict(myQueue, id, NF_ACCEPT, len, pktData); // accept all TCP packets unless rejected previously.
	}

	return nfq_set_verdict(myQueue, id, NF_DROP, len, pktData); //reject non TCP packets

	// end Callback
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
	i;

	for (i = 0; i < padding; i++)
	{

		strcat(ip_address, " ");
	}
	printf("%s", ip_address);
}

void print_nat(struct nat *nat)
{
	struct nat *temp = nat;
	printf("\n  NAT:\n  ");
	while (temp != NULL)
	{
		print_ip(temp->src_ip);
		printf("| %5u |", temp->src_port);
		print_ip(temp->translated_ip);
		printf(" | %5u | %10u | %10u | %c | %c |", temp->nat_port, temp->internal_flag_ack, temp->external_flag_ack, temp->internal_fin, temp->external_fin);

		{
			printf("\n  ");
		}
		temp = temp->next;
	}
	printf("\n");
}
// determine if the packet is outbound or inbound
int verify_subnet(unsigned int lan_ip, unsigned int src_ip, int mask)
{
	unsigned int local_mask = 0xffffffff << (32 - mask);

	if ((ntohl(lan_ip) & local_mask) == (ntohl(src_ip) & local_mask))
	{

		return 1;
	}
	else
	{

		return 0;
	}
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
		pre->next = new_node;
		new_node->nat_port = pre->nat_port + 1;
		new_node->next = cur;
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
	{
		*head = ((*head)->next);
	}
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
	struct nfq_handle *nfqHandle;
	struct cbdata cb_data;
	cb_data.ip = inet_addr(argv[1]);
	cb_data.subnet = inet_addr(argv[2]);
	cb_data.mask = (unsigned int)atoi(argv[3]);
	cb_data.nat = (struct nat **)malloc(sizeof(struct nat *));
	*(cb_data.nat) = NULL;
	struct nfq_q_handle *myQueue;
	struct nfnl_handle *netlinkHandle;

	int fd, res;
	char buf[4096];

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

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0)
	{
		// I am not totally sure why a callback mechanism is used
		// rather than just handling it directly here, but that
		// seems to be the convention...
		nfq_handle_packet(nfqHandle, buf, res);
		// end while receiving traffic
	}

	nfq_destroy_queue(myQueue);

	nfq_close(nfqHandle);

	return 0;

	// end main
}
