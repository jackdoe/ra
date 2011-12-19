#include <stdio.h>
#include <stdlib.h>
//TEXTY_EXECUTE gcc -Wall -O3 -lpcap -o {MYDIR}/{MYSELF_BASENAME_NOEXT} {MYSELF} && {MYDIR}/{MYSELF_BASENAME_NOEXT} -i en1 -p 2a02:6800:ff60:c1fb:: {NOTIMEOUT}
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
	u32 generator_interval;

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
int main(int ac, char *av[]) {
	int ch;
	bzero(&g,sizeof(g));
	g.generator_interval = 1;
	g.prefix_len = 64;
	while ((ch = getopt(ac, av, "i:p:l")) != -1) {
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
void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) {
	if (!sp || h->len < sizeof(struct rs_pkt))
		return;
		
	struct rs_pkt *rs = (struct rs_pkt *) sp;
	if (rs->ip.ip6_nxt == IPPROTO_ICMPV6 && 
	    rs->rs.nd_rs_hdr.icmp6_type == ND_ROUTER_SOLICIT) {
		// enqueue
	}
	_DETH(rs->eh);	
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
	radvert->nd_ra_flags_reserved	= (ND_RA_FLAG_MANAGED | ND_RA_FLAG_RTPREF_HIGH);
	radvert->nd_ra_router_lifetime	 =  htons(60);
	radvert->nd_ra_reachable  = htonl(60);
	radvert->nd_ra_retransmit = htonl(60);

	struct nd_opt_prefix_info *pinfo = &ra->px;
	pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	pinfo->nd_opt_pi_len = 4;
	pinfo->nd_opt_pi_prefix_len = g.prefix_len;
	pinfo->nd_opt_pi_flags_reserved = (ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO);
	pinfo->nd_opt_pi_valid_time = 0xffffffff;
	pinfo->nd_opt_pi_preferred_time = 0xffffffff;
	pinfo->nd_opt_pi_reserved2 = 0;
	ICOPY(&g.prefix,&pinfo->nd_opt_pi_prefix);

	struct nd_opt_mtu *mtu = &ra->mtu;
	mtu->nd_opt_mtu_type     = ND_OPT_MTU;
	mtu->nd_opt_mtu_len      = 1;
	mtu->nd_opt_mtu_reserved = 0; 
	mtu->nd_opt_mtu_mtu      = htonl(1500);
	
	struct nd_opt_lla *lla = &ra->lla;
	int optlen = sizeof(struct nd_opt_hdr) + ETHER_ADDR_LEN;
	optlen = (optlen + 7) & ~7;
	lla->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	lla->nd_opt_len = optlen >> 3;;
	ECOPY(g.mac,lla->mac);
	//	ip6_checksum(ip,plen);
	enqueue(packet);
}

