#include "skel.h"
#define BROADCAST "ff:ff:ff:ff:ff:ff"
#include <string.h>
#include <stdio.h>
#include <math.h>

struct route_table_entry *rtable;
int rtable_size;

// binary search for logn search in route table //longest prefix match
struct route_table_entry *get_best_route(__u32 dest_ip) {

	int l = 0, r = rtable_size-1;
	while (l <= r) {
		int m = floor((r + l) / 2);
		if ((rtable[m].mask & dest_ip) == rtable[m].prefix) {
			while ((rtable[m].mask & dest_ip) == rtable[m].prefix) {
				m--;
			}
			return &rtable[m+1];
		}
		if (ntohl(rtable[m].prefix) > ntohl((rtable[m].mask & dest_ip))) {
			r = m-1;

		} else if (ntohl(rtable[m].prefix) < ntohl((rtable[m].mask & dest_ip))){
			l = m+1;
		}
	}

	return NULL;
}

struct arp_entry *arp_table;
int arp_table_len;

struct arp_entry *get_arp_entry(__u32 ip) {

	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}

    return NULL;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init();
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	arp_table = malloc(sizeof(struct arp_entry) * 5);
	DIE(rtable == NULL, "memory");
	rtable_size = read_rtable(rtable);
	parse_arp_table();

	qsort((void *)rtable, rtable_size, sizeof(struct route_table_entry), comparator);

	while (1) {
		rc = get_packet(&m);

		DIE(rc < 0, "get_message");
		/* Students will write code here */
		
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

		if (ip_checksum(ip_hdr, sizeof(struct iphdr)) != ntohs(0)) {
			// bad checksum
			continue;
		}
		struct route_table_entry *match = get_best_route(ip_hdr->daddr);
		// icmp destination unreachable
		if (match == NULL) {

			struct arp_entry *table = get_arp_entry(ip_hdr->saddr);
			packet host_unreachable;
			memset(host_unreachable.payload, 0, sizeof(host_unreachable.payload));
			host_unreachable.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

			eth_hdr = (struct ether_header *)host_unreachable.payload;
			ip_hdr = (struct iphdr *)(host_unreachable.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *) (host_unreachable.payload + sizeof(struct iphdr) +
														sizeof(struct ether_header));

			eth_hdr->ether_type = htons(ETHERTYPE_IP);
			get_interface_mac(m.interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, table->mac, 6);

			// ip header
			ip_hdr->version = 4;
			ip_hdr->ihl = 5;
			ip_hdr->tos = 0;
			ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			ip_hdr->id = htons(0);
			ip_hdr->frag_off = 0;
			ip_hdr->ttl = 1;
			ip_hdr->protocol = IPPROTO_ICMP;
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

			// icmp header
			icmp_hdr->type = ICMP_DEST_UNREACH;
			icmp_hdr->code = 0;
			icmp_hdr->un.echo.id = 0;
			icmp_hdr->un.echo.sequence = htons(1);
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));
			rc = send_packet(m.interface, &host_unreachable);
			continue;
		}

		// icmp router
		if (inet_addr(get_interface_ip(match->interface)) == ip_hdr->daddr) {
			
			struct arp_entry *table = get_arp_entry(ip_hdr->saddr);
			packet router_icmp;
			memset(router_icmp.payload, 0, sizeof(router_icmp.payload));
			router_icmp.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

			eth_hdr = (struct ether_header *)router_icmp.payload;
			ip_hdr = (struct iphdr *)(router_icmp.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *) (router_icmp.payload + sizeof(struct iphdr) +
														sizeof(struct ether_header));

			eth_hdr->ether_type = htons(ETHERTYPE_IP);
			get_interface_mac(m.interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, table->mac, 6);

			//ip header
			ip_hdr->version = 4;
			ip_hdr->ihl = 5;
			ip_hdr->tos = 0;
			ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			ip_hdr->id = htons(0);
			ip_hdr->frag_off = 0;
			ip_hdr->ttl = 1;
			ip_hdr->protocol = IPPROTO_ICMP;
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

			//icmp header
			icmp_hdr->type = ICMP_ECHOREPLY;
			icmp_hdr->code = 0;
			icmp_hdr->un.echo.id = 0;
			icmp_hdr->un.echo.sequence = htons(1);
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));
			rc = send_packet(m.interface, &router_icmp);
			continue;
		}

		struct arp_entry *table = get_arp_entry(match->next_hop);

		ip_hdr->ttl--;
		
		// icmp time limit exceeded
		if (ip_hdr->ttl <= 0) {

			table = get_arp_entry(ip_hdr->daddr);
			packet icmp_timeout;
			memset(icmp_timeout.payload, 0, sizeof(icmp_timeout.payload));
			icmp_timeout.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
			
			eth_hdr = (struct ether_header *)icmp_timeout.payload;
			ip_hdr = (struct iphdr *)(icmp_timeout.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *) (icmp_timeout.payload + sizeof(struct iphdr) +
														sizeof(struct ether_header));
			
			eth_hdr->ether_type = htons(ETHERTYPE_IP);
			get_interface_mac(m.interface, eth_hdr->ether_shost);
			memcpy(eth_hdr->ether_dhost, table->mac, 6);

			//ip header
			ip_hdr->version = 4;
			ip_hdr->ihl = 5;
			ip_hdr->tos = 0;
			ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
			ip_hdr->id = htons(0);
			ip_hdr->frag_off = 0;
			ip_hdr->ttl = 1;
			ip_hdr->protocol = IPPROTO_ICMP;
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

			// icmp header
			icmp_hdr->type = ICMP_TIME_EXCEEDED;
			icmp_hdr->code = 0;
			icmp_hdr->un.echo.id = 0;
			icmp_hdr->un.echo.sequence = htons(1);
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = checksum(icmp_hdr, sizeof(struct icmphdr));
			
			rc = send_packet(match->interface, &icmp_timeout);
			continue;
		}

		// complete ether_header fields
		eth_hdr->ether_type = htons(ETHERTYPE_IP);
		get_interface_mac(match->interface, eth_hdr->ether_shost);
		memcpy(eth_hdr->ether_dhost, table->mac, 6);
		
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
		
		// forward m
		if (ETHERTYPE_IP == ntohs(eth_hdr->ether_type)) {
			rc = send_packet((get_best_route(ip_hdr->daddr))->interface, &m);
			DIE(rc < 0, "couldn't send packet");
		}
	}
}

/*
de facut implementare protocol arp
-> merge foarte bine sa trimita boradcast
-> nu sunt in stare sa adaug intrare in tabela arp
if (ETHERTYPE_ARP == ntohs(eth_hdr->ether_type)) {
			packet router_arp_reply;
			memset(router_arp_reply.payload, 0, sizeof(router_arp_reply.payload));
			router_arp_reply.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

			struct ether_header *eth_reply = (struct ether_header *)router_arp_reply.payload;
			struct ether_arp *arp_reply = (struct ether_arp *)(router_arp_reply.payload + sizeof(struct ether_header));

			eth_reply->ether_type = htons(ETHERTYPE_ARP);
			memcpy(eth_reply->ether_dhost, eth_hdr->ether_shost, 6);
			get_interface_mac(m.interface, eth_reply->ether_shost);

			arp_reply->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
			arp_reply->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
			arp_reply->ea_hdr.ar_hln = 6;
			arp_reply->ea_hdr.ar_pln = 4;
			arp_reply->ea_hdr.ar_op = htons(ARPOP_REPLY);

			char ip_dest[4];
			ip_dest[0] = ip_hdr->saddr & 0xFF;
			ip_dest[1] = (ip_hdr->saddr >> 8) & 0xFF;
			ip_dest[2] = (ip_hdr->saddr >> 16) & 0xFF;
			ip_dest[3] = (ip_hdr->saddr >> 24) & 0xFF;

			get_interface_mac(m.interface, arp_reply->arp_sha);
			memcpy(arp_reply->arp_tha, eth_hdr->ether_shost, 6);
			//memcpy(arp_reply->arp_spa, (const void *)inet_addr(get_interface_ip(m.interface)), 4);
			int ip_source = inet_addr(get_interface_ip(m.interface));
			arp_reply->arp_spa[3] = ip_source & 0xFF;
			arp_reply->arp_spa[2] = (ip_source >> 8) & 0xFF;
			arp_reply->arp_spa[1] = (ip_source >> 16) & 0xFF;
			arp_reply->arp_spa[0] = (ip_source >> 24) & 0xFF;
			uint8_t aux;
			for (int i = 0; i < 2; i++) {
				aux = arp_reply->arp_spa[i];
				arp_reply->arp_spa[i] = arp_reply->arp_spa[4-i-1];
				arp_reply->arp_spa[4-i-1] = aux;
			}
			memcpy(arp_reply->arp_tpa, ip_dest, 4);
			
			send_packet(m.interface, &router_arp_reply);
			continue;
		}

struct arp_entry *table;
		if (arp_table != NULL) {
			table = get_arp_entry(match->next_hop);	
		}
		
		if (table == NULL) {
			queue packets = queue_create();
			queue_enq(packets, &m);
			packet arp_request;
			memset(arp_request.payload, 0, sizeof(arp_request.payload));
			arp_request.len = sizeof(struct ether_header) + sizeof(struct ether_arp);

			struct ether_header *eth_req = (struct ether_header *)arp_request.payload;
			struct ether_arp *arp_req = (struct ether_arp *)(arp_request.payload + sizeof(struct ether_header));

			eth_req->ether_type = htons(ETHERTYPE_ARP);
			hwaddr_aton(BROADCAST, eth_req->ether_dhost);

			arp_req->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
			arp_req->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
			arp_req->ea_hdr.ar_hln = 6;
			arp_req->ea_hdr.ar_pln = 4;
			arp_req->ea_hdr.ar_op = htons(ARPOP_REQUEST);

			hwaddr_aton(BROADCAST, arp_req->arp_tha);
			uint32_t next_hop = match->next_hop;
			char ip_dest[4];
			ip_dest[0] = next_hop & 0xFF;
			ip_dest[1] = (next_hop >> 8) & 0xFF;
			ip_dest[2] = (next_hop >> 16) & 0xFF;
			ip_dest[3] = (next_hop >> 24) & 0xFF;
			memcpy(arp_req->arp_tpa, ip_dest, 4);
			for (int i = 0; i < 4; i++) {
				int ip_source = inet_addr(get_interface_ip(i));
				arp_req->arp_spa[3] = ip_source & 0xFF;
				arp_req->arp_spa[2] = (ip_source >> 8) & 0xFF;
				arp_req->arp_spa[1] = (ip_source >> 16) & 0xFF;
				arp_req->arp_spa[0] = (ip_source >> 24) & 0xFF;
				uint8_t aux;
				for (int i = 0; i < 2; i++) {
					aux = arp_req->arp_spa[i];
					arp_req->arp_spa[i] = arp_req->arp_spa[4-i-1];
					arp_req->arp_spa[4-i-1] = aux;
				}
				get_interface_mac(i, eth_req->ether_shost);
				get_interface_mac(i, arp_req->arp_sha);
				arp_request.interface = i;
				send_packet(i, &arp_request);
			}
			packet arp_reply;
			get_packet(&arp_reply);
			struct ether_header *eth_rep = (struct ether_header *)arp_reply.payload;

				struct ether_arp *arp_rep = (struct ether_arp *)(arp_reply.payload + sizeof(struct ether_header));
				
				//struct arp_entry *entry;
				//entry = malloc(sizeof(struct arp_entry));
				memcpy(arp_table[index].mac, eth_rep->ether_shost, 6);
				
				char sender_addr[4];
				
				memcpy(sender_addr, arp_rep->arp_spa, 4);
				
				arp_table[index].ip = inet_addr(sender_addr);
				//sarp_table[index] = *entry;
				index++;
				arp_table_len++;

			m = *((packet *)queue_deq(packets));
			//return 0;
			//printf("%d", arp_table[index].ip);
			table = get_arp_entry(match->next_hop);
			if (table == NULL) {
				//return 0;
			}
			//return 0;
			printf("%d", table->ip);
			//return 0;
		}
*/
