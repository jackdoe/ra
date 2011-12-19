#include <stdio.h>
#include <stdlib.h>
//TEXTY_EXECUTE gcc -Wall -O3 -lpcap -o {MYDIR}/{MYSELF_BASENAME_NOEXT} {MYSELF} && {MYDIR}/{MYSELF_BASENAME_NOEXT} -i en0 -p  dead:beef:dead:beef:: -t 1 -f "ra_managed ra_pref_high" -r 4294967295:4294967295:80:80:80 {NOTIMEOUT}
/* 
 * to build it type: gcc -O2 -lpcap -o ra ra.c
 * to run it: ./ra -i interface -p prefix -l prefix_len (default 64)
 */
/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <jack@brokensociety.org> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Borislav Nikolov
 * ----------------------------------------------------------------------------
 */
 
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <pcap.h>
#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/queue.h>
#define ETHER_ADDR_LEN 6
#define CMP(a,b,len) (bcmp(a,b,len) == 0)
#define COPY(a,b,len) bcopy(a,b,len)
#define ICOPY(a,b) COPY(a,b,sizeof(struct in6_addr))
#define ICMP(a,b) CMP(a,b,sizeof(struct in6_addr))
#define ECOPY(a,b) COPY(a,b,ETHER_ADDR_LEN)
#define ECMP(a,b) CMP(a,b,ETHER_ADDR_LEN)
#define __packed __attribute__ ((__packed__))

#define P_ETH "%02x:%02x:%02x:%02x:%02x:%02x"
#define P_ETHARG(addr) (u8) addr[0],(u8) addr[1],(u8) addr[2],(u8) addr[3],(u8) addr[4],(u8) addr[5]
#define _D(fmt,arg...) printf(fmt " [%s():%s:%d]\n", ##arg,__func__,__FILE__,__LINE__)
#define _DETH(eh) _D("etype:%X shost: " P_ETH " dhost " P_ETH,ntohs(eh.ether_type),P_ETHARG(eh.ether_shost),P_ETHARG(eh.ether_dhost))
#define SAYX(rc,fmt,arg...) do {									\
	_D(fmt,##arg); 												\
	exit(rc);													\
} while(0);


/* 
 * from libdnet's ip-util.c, read below for license
 */
#define ip_cksum_carry(x) 										\
	    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

struct nd_opt_lla {
	u8 nd_opt_type;
	u8 nd_opt_len;
	u8 mac[ETHER_ADDR_LEN];
} __packed;
struct rs_pkt {
	struct ether_header eh;
	struct ip6_hdr ip;
	struct nd_router_solicit rs;
	u8 options[0];
} __packed;
struct ns_pkt {
	struct ether_header eh;
	struct ip6_hdr ip;
	struct nd_neighbor_solicit ns;
} __packed;

struct na_pkt {
	struct ether_header eh;
	struct ip6_hdr ip;
	struct nd_neighbor_advert na;
	struct nd_opt_lla lla;
} __packed;

struct ra_pkt {
	struct ether_header eh;
	struct ip6_hdr ip;
	struct nd_router_advert ra;
	struct nd_opt_prefix_info px;
	struct nd_opt_mtu mtu;
	struct nd_opt_lla lla;
} __packed;

struct sendit {
	struct ra_pkt ra;
	TAILQ_ENTRY(sendit) list;
};
struct send_queue {
	TAILQ_HEAD(,sendit) head;
	pthread_mutex_t lock;	
};
struct global {
	u8 mac[ETHER_ADDR_LEN];
	char *ifname;
	pcap_t *cap;
	char	errbuf[PCAP_ERRBUF_SIZE];

	struct in6_addr fe80;
	struct in6_addr prefix;
	u8 prefix_len;
	u16 mtu;
	u32 generator_interval;
	u32 ra_lifetime;
	u32 ra_reachable;
	u32 ra_retransmit;
	u32 ra_flags;
	u32 pi_flags;
	u32 pi_valid_time;
	u32 pi_preferred_time;
	pthread_cond_t cond;
	pthread_mutex_t cond_lock;
	struct send_queue q;
} g;

u8 all_hosts_in6_addr[] = {0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
u8 all_multi_eth_addr[] = {0x33,0x33,0x00,0x00,0x00,0x01};

int process_if(char *ifname);
void	pcap_callback(u_char *user, const struct pcap_pkthdr *h,const u_char *sp);
void ip6_checksum(void *buf, size_t len);
void *ra_listen(void *v);
void *ra_send(void *v);
void *ra_generator(void *v);
void enqueue(struct sendit *packet);
void process_queue(void);
void generate_ra(u8 *edest);
void init_go_and_die_cleanly(void);
void ip_checksum(void *buf, size_t len);
int ip_cksum_add(const void *buf, size_t len, int cksum);
void usage(void);
int main(int ac, char *av[]) {
	int ch,v;
	bzero(&g,sizeof(g));
	g.generator_interval = 30;
	g.prefix_len = 64;
	g.mtu = 1500;
	g.pi_valid_time = 0xFFFFFFFF;
	g.pi_preferred_time = 0xFFFFFFFF;
	g.pi_flags = (ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO);
	g.ra_flags =  (ND_RA_FLAG_MANAGED);
	g.ra_lifetime = 60;
	g.ra_reachable = 60;
	g.ra_retransmit = 60;
	g.ifname = "em0";
	while ((ch = getopt(ac, av, "i:p:lmh?t:f:r:")) != -1) {
		switch(ch) {
		case 'i':
			g.ifname = strdup(optarg);
		break;
		case 'p':
			inet_pton(AF_INET6,optarg,&g.prefix);
		break;
		case 'l':
			g.prefix_len = atoi(optarg);
		break;
		case 'm': /* managed */
			g.mtu = atoi(optarg);
		break;
		case 't':
			v = atoi(optarg);
			g.generator_interval = (v > 0) ? v : g.generator_interval;
		break;
		case 'r':
			{
				u32 b[5];
				/* pi_valid_time:pi_preferred_time:ra_lifetime:ra_reachable:ra_retransmit */
				if (sscanf(optarg,"%d:%d:%d:%d:%d",&b[0],&b[1],&b[2],&b[3],&b[4]) == 5) {
					#define valid(idx,var,failmsg) do {					\
					if (b[idx] > 0) 								\
						var = b[idx];								\
					else											\
						SAYX(1,failmsg);							\
					} while(0);
					valid(0,g.pi_valid_time,"ivalid pi_valid_time");
					valid(1,g.pi_preferred_time,"invalid pi_preferred_time");
					valid(2,g.ra_lifetime,"invalid ra_lifetime");
					valid(3,g.ra_reachable,"invalid ra_reachable");
					valid(4,g.ra_retransmit,"invalid ra_retransmit");
					#undef valid
				}
			}
		break;
		case 'f':
			/* all kinds of flags */
			#define CLEAR 1
			#define NOCLEAR 0
			#define exists(a,flag,var,clear) do { 						\
				if (strstr(optarg,a) != NULL)	{						\
					var |= flag;									\
				} else {											\
					if (clear)										\
						var &= ~flag;								\
				}												\
			} while (0);
			
			exists("pi_onlink",ND_OPT_PI_FLAG_ONLINK,g.pi_flags,CLEAR);
			exists("pi_autonomous", ND_OPT_PI_FLAG_AUTO,g.pi_flags,CLEAR);
			exists("ra_managed", ND_RA_FLAG_MANAGED,g.ra_flags,CLEAR);
			exists("ra_ha", ND_RA_FLAG_HA,g.ra_flags,CLEAR);			
			exists("ra_otner", ND_RA_FLAG_OTHER,g.ra_flags,CLEAR);
			exists("ra_pref_high", ND_RA_FLAG_RTPREF_HIGH,g.ra_flags,NOCLEAR);
			exists("ra_pref_low", ND_RA_FLAG_RTPREF_LOW,g.ra_flags,NOCLEAR);
			#undef exists
			#undef CLEAR
			#undef NOCLEAR
		break;
		
		case '?':
		case 'h':
			usage();
		break;
		}
	}
	
	if (ICMP(&g.prefix,&in6addr_any)) 
		SAYX(1,"need to specify valid ipv6 prefix");

	process_if(g.ifname);
	init_go_and_die_cleanly();
	return 0;
}
void init_go_and_die_cleanly(void) {
	pthread_t t[3];
	int i;
	pthread_mutex_init(&g.q.lock, NULL);
	pthread_mutex_init(&g.cond_lock,NULL);
	pthread_cond_init(&g.cond,NULL);
	TAILQ_INIT(&g.q.head);
	if (pthread_create(&t[0],NULL,ra_listen,NULL)) 
		SAYX(1,"pthread: failed to create thread");
	if (pthread_create(&t[1],NULL,ra_send,NULL)) 
		SAYX(1,"pthread: failed to create thread");
	if (pthread_create(&t[2],NULL,ra_generator,NULL)) 
		SAYX(1,"pthread: failed to create thread");
		
	/* wait for them */
	for (i=0;i<3;i++) {
		pthread_join(t[i],NULL);
	}
	pthread_mutex_destroy(&g.q.lock);
	pthread_mutex_destroy(&g.cond_lock);
	pthread_cond_destroy(&g.cond);
}
void *ra_listen(void *v) {
	if (pcap_loop(g.cap, 0, pcap_callback, NULL) < 0)
		SAYX(1,"pcap_loop(%s): %s", g.ifname, pcap_geterr(g.cap));
	return NULL;
}

void *ra_send(void *v) {
	for(;;) {
		process_queue();
		pthread_mutex_lock(&g.cond_lock);
		pthread_cond_wait(&g.cond,&g.cond_lock);
		pthread_mutex_unlock(&g.cond_lock);
	}
	return NULL;
}

void *ra_generator(void *v) {
	for (;;) {
		generate_ra(NULL);
		sleep(g.generator_interval);
	}
	return NULL;
}
void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) {
	if (!sp || h->len < sizeof(struct rs_pkt))
		return;
		
	struct rs_pkt *rs = (struct rs_pkt *) sp;
	if (rs->ip.ip6_nxt == IPPROTO_ICMPV6 && 
	    rs->rs.nd_rs_hdr.icmp6_type == ND_ROUTER_SOLICIT) {
		generate_ra(rs->eh.ether_shost);
	}
//	_DETH(rs->eh);
}

void generate_ra(u8 *edest) {
	struct sendit *packet = malloc(sizeof(*packet));
	if (!packet) {
		_D("not enough mem to allocate: %lu bytes",sizeof(*packet));
		return;
	}
	bzero(packet,sizeof(*packet));
	struct ra_pkt *ra = &packet->ra;
	u16 plen = sizeof(*ra) - sizeof(struct ether_header) - sizeof(struct ip6_hdr);
	ECOPY(g.mac,&ra->eh.ether_shost);
	if (edest) 
		ECOPY(edest,&ra->eh.ether_dhost);
	else 
		ECOPY(all_multi_eth_addr,&ra->eh.ether_dhost);
	ra->eh.ether_type = htons(ETHERTYPE_IPV6);
	
	struct ip6_hdr *ip = &ra->ip;
	ICOPY(&g.fe80,&ip->ip6_src);
	ICOPY(all_hosts_in6_addr,&ip->ip6_dst);
	ip->ip6_flow = 0;
	ip->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip->ip6_vfc |= IPV6_VERSION;
	ip->ip6_nxt = IPPROTO_ICMPV6;
	ip->ip6_hlim = 255;
	ip->ip6_plen = htons(plen);
	
	struct nd_router_advert *radvert = &ra->ra;
	radvert->nd_ra_type  = ND_ROUTER_ADVERT;
	radvert->nd_ra_code  = 0;
	radvert->nd_ra_cksum = 0;
	radvert->nd_ra_curhoplimit	= 64;
	radvert->nd_ra_flags_reserved	= g.ra_flags;
	radvert->nd_ra_router_lifetime	 =  htons(g.ra_lifetime);
	radvert->nd_ra_reachable  = htonl(g.ra_reachable);
	radvert->nd_ra_retransmit = htonl(g.ra_retransmit);

	struct nd_opt_prefix_info *pinfo = &ra->px;
	pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	pinfo->nd_opt_pi_len = 4;
	pinfo->nd_opt_pi_prefix_len = g.prefix_len;
	pinfo->nd_opt_pi_flags_reserved = g.pi_flags;
	pinfo->nd_opt_pi_valid_time = htonl(g.pi_valid_time);
	pinfo->nd_opt_pi_preferred_time = htonl(g.pi_preferred_time);
	pinfo->nd_opt_pi_reserved2 = 0;
	ICOPY(&g.prefix,&pinfo->nd_opt_pi_prefix);

	struct nd_opt_mtu *mtu = &ra->mtu;
	mtu->nd_opt_mtu_type     = ND_OPT_MTU;
	mtu->nd_opt_mtu_len      = 1;
	mtu->nd_opt_mtu_reserved = 0; 
	mtu->nd_opt_mtu_mtu      = htonl(g.mtu);
	
	struct nd_opt_lla *lla = &ra->lla;
	int optlen = sizeof(struct nd_opt_hdr) + ETHER_ADDR_LEN;
	optlen = (optlen + 7) & ~7;
	lla->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	lla->nd_opt_len = optlen >> 3;;
	ECOPY(g.mac,lla->mac);

	int sum = ip_cksum_add(radvert, plen, 0) + htons(IPPROTO_ICMPV6 + plen);
	sum = ip_cksum_add(&ip->ip6_src, 32, sum);
	radvert->nd_ra_cksum = ip_cksum_carry(sum);
	enqueue(packet);
}


void enqueue(struct sendit *packet) {
	pthread_mutex_lock(&g.q.lock);
	TAILQ_INSERT_TAIL(&g.q.head,packet,list);
	pthread_mutex_unlock(&g.q.lock);

	pthread_mutex_lock(&g.cond_lock);
	pthread_cond_signal(&g.cond);
	pthread_mutex_unlock(&g.cond_lock);
}
void process_queue(void) {
	pthread_mutex_lock(&g.q.lock);
	struct sendit *packet, *packet_temp;
	TAILQ_FOREACH_SAFE(packet,&g.q.head,list,packet_temp) {
		pcap_inject(g.cap,&packet->ra,sizeof(packet->ra));
		TAILQ_REMOVE(&g.q.head,packet,list);
		free(packet);
	}
	pthread_mutex_unlock(&g.q.lock);
}
int process_if(char *ifname) {
	struct ifaddrs *ifas, *ifa;
	struct in6_addr *ip;
	int found = 0;
	struct bpf_program fp;

	if (!ifname || getifaddrs(&ifas) == -1) 
		SAYX(1,"failed to process interface: %s",g.ifname);
	
	for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp (ifa->ifa_name, g.ifname))
			continue;
#define SDL ((struct sockaddr_dl *)ifa->ifa_addr)
		if (SDL->sdl_family == AF_INET6) {
			ip = &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
			if (IN6_IS_ADDR_LINKLOCAL(ip)) {
				ICOPY(ip,&g.fe80);
				found = 1;
			}
		} else if (SDL->sdl_family == AF_LINK && SDL->sdl_alen == ETHER_ADDR_LEN) {
			ECOPY(SDL->sdl_data + SDL->sdl_nlen, g.mac);
		}
	}
#undef SDL
	freeifaddrs(ifas);
	if (!found) 
		SAYX(1,"no fe80 found on %s",g.ifname);
  	if ((g.cap = pcap_open_live(g.ifname, 1500, 0, 100, g.errbuf)) == NULL)
		SAYX(1, "pcap_open_live(): %s", g.errbuf);
	if (pcap_compile(g.cap, &fp, "icmp6", 0, 0) < 0)
		SAYX(1,"pcap_compile: %s", pcap_geterr(g.cap));
	if (pcap_setfilter(g.cap, &fp) < 0)
		SAYX(1,"pcap_setfilter: %s", pcap_geterr(g.cap));
	return 1;
}

void usage(void) {
	printf("ra -i ifname(em0) -l prefix_len(64) -p prefix -m mtu(1500) -f flags (read below) -r times(read below) -l advertise_interval(default 30 seconds)\n");
	printf("so if you run ra -p dead:beef:dead:beef:: will run it with:\n");
	printf("by default the parameters are: ra -i em0 -m 1500 -l 64 -p dead:beef:dead:beef:: -f 'ra_managed' -t 30 -r 4294967295:4294967295:60:60:60\n");
	printf("\nsee RFC 4862 for more info\n");
	printf("available flags: pi_onlink pi_autonomous ra_managed ra_ha ra_other ra_pref_(high|low)\n");
	printf("\tflags must be in 1 argument eg.: -f \"ra_managed ra_pref_medium pi_onlink\"\n");
	printf("available times: pi_valid_time:pi_preferred_time:ra_lifetime:ra_reachable:ra_retransmit\n");
	printf("\t must be in 1 argument, and all defined eg.: -r 4294967295:4294967295:60:60:60\n");
	printf("\t\tpi_valid_time:4294967295 - infinity, specify prefix valid time\n");
	printf("\t\tpi_preferred_time:4294967295 - infinity, specify prefix preferred time\n");
	exit(1);
}
/*---------------------------------------------------------------------------*/

/*
 Copyright (c) 2000-2006 Dug Song <dugsong@monkey.org>
 All rights reserved, all wrongs reversed.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 
 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 3. The names of the authors and copyright holders may not be used to
 endorse or promote products derived from this software without
 specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 * ip-util.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ip-util.c,v 1.9 2005/02/17 02:55:56 dugsong Exp $
 */

int ip_cksum_add(const void *buf, size_t len, int cksum)
{
	uint16_t *sp = (uint16_t *)buf;
	int n, sn;
	
	sn = len / 2;
	n = (sn + 15) / 16;

	/* XXX - unroll loop using Duff's device. */
	switch (sn % 16) {
	case 0:	do {
		cksum += *sp++;
	case 15:
		cksum += *sp++;
	case 14:
		cksum += *sp++;
	case 13:
		cksum += *sp++;
	case 12:
		cksum += *sp++;
	case 11:
		cksum += *sp++;
	case 10:
		cksum += *sp++;
	case 9:
		cksum += *sp++;
	case 8:
		cksum += *sp++;
	case 7:
		cksum += *sp++;
	case 6:
		cksum += *sp++;
	case 5:
		cksum += *sp++;
	case 4:
		cksum += *sp++;
	case 3:
		cksum += *sp++;
	case 2:
		cksum += *sp++;
	case 1:
		cksum += *sp++;
		} while (--n > 0);
	}
	if (len & 1)
		cksum += htons(*(u_char *)sp << 8);

	return (cksum);
}


