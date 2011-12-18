#include <stdio.h>
#include <stdlib.h>
//TEXTY_EXECUTE gcc -Wall -lpcap -o {MYDIR}/{MYSELF_BASENAME_NOEXT} {MYSELF} && {MYDIR}/{MYSELF_BASENAME_NOEXT} {MYSELF} {NOTIMEOUT}
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <err.h>
#include <pcap.h>

#define ETHER_ADDR_LEN 6
#define CMP(a,b,len) bcmp(a,b,len)
#define COPY(a,b,len) bcopy(a,b,len)
#define ECOPY(a,b) COPY(a,b,ETHER_ADDR_LEN)
#define ECMP(a,b) CMP(a,b,ETHER_ADDR_LEN)
#define __packed __attribute__ ((__packed__))

#define P_ETH "%02x:%02x:%02x:%02x:%02x:%02x"
#define P_ETHARG(addr) (u8) addr[0],(u8) addr[1],(u8) addr[2],(u8) addr[3],(u8) addr[4],(u8) addr[5]
#define _D(fmt,arg...) printf(fmt " [%s():%s:%d]\n", ##arg,__func__,__FILE__,__LINE__)
#define _DETH(eh) _D("etype:%X shost: " P_ETH " dhost " P_ETH,ntohs(eh->ether_type),P_ETHARG(eh->ether_shost),P_ETHARG(eh->ether_dhost))

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

struct nd_opt_lla {
	u8 nd_opt_type;
	u8 nd_opt_len;                
	u8 mac[ETHER_ADDR_LEN];
} __packed;
struct na_pkt {
	struct ether_header eh;
	struct ip6_hdr ip;
	struct nd_neighbor_advert na;
	struct nd_opt_lla lla;
} __packed;
struct nd_opt_route_info_local {
	u8 	nd_opt_ri_type;
	u8	nd_opt_ri_len;
	u8	nd_opt_ri_prefix_len;
	u8	nd_opt_ri_flags_reserved;
	u32	nd_opt_ri_lifetime;
	struct in6_addr nd_opt_ri_prefix;   
} __packed;
struct ra_pkt {
	struct ether_header eh;
	struct ip6_hdr ip;
	struct nd_router_advert ra;
	struct nd_opt_prefix_info px;
	struct nd_opt_mtu mtu;
	struct nd_opt_lla lla;
} __packed;

void	pcap_callback(u_char *user, const struct pcap_pkthdr *h,const u_char *sp);
u8 all_hosts_in6_addr[] = {0xff,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
u8 all_multi_eth_addr[] = {0x33,0x33,0x00,0x00,0x00,0x01};
pcap_t *cap;

int main(int ac, char *av[]) {
	char	errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char *ifname = "en1";
  	if ((cap = pcap_open_live(ifname, 1500, 0, 100, errbuf)) == NULL)
		errx(1, "pcap_open_live(): %s", errbuf);
	if (pcap_compile(cap, &fp, "icmp6", 0, 0) < 0)
		errx(1,"pcap_compile: %s", pcap_geterr(cap));
	if (pcap_setfilter(cap, &fp) < 0)
		errx(1,"pcap_setfilter: %s", pcap_geterr(cap));
	if (pcap_loop(cap, 0, pcap_callback, NULL) < 0)
		errx(1,"pcap_loop(%s): %s", ifname, pcap_geterr(cap));
        

	return 0;
}

void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *sp) {
	if (!sp || h->len == 0)
		return;
	struct ether_header *eh = (struct ether_header *) sp;
	_DETH(eh);
}


//void send_ra(u16 tag,u_char *edest) {
//	struct ra_pkt ra;
//	bzero(&ra,sizeof(ra));
//	ECOPY(cujo_global.mac_em1,&ra.eh.ether_shost);
//	ECOPY(edest,&ra.eh.ether_dhost);
//	ra.eh.ether_type = htons(ETHERTYPE_IPV6);
//	struct ip6_hdr *ip6 = &ra.ip;
//	
//	ICOPY(all_hosts_addr,&ip6->ip6_dst);
//	ICOPY(&cujo_global.fe80_em1,&ip6->ip6_src);
//	add_tag_to_fe80(tag,&ip6->ip6_src);
//	ip6->ip6_flow = 0;
//	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
//	ip6->ip6_vfc |= IPV6_VERSION;
//	ip6->ip6_nxt = IPPROTO_ICMPV6;
//	ip6->ip6_hlim = 255;
//	ip6->ip6_plen = htons(sizeof(ra) - sizeof(struct ether_header) - sizeof(struct ip6_hdr)); 
//	struct in6_addr prefix = cujo_global.prefix_em1;
//	tagit(&prefix,tag);
//
//	struct nd_router_advert *radvert = &ra.ra;
//	radvert->nd_ra_type  = ND_ROUTER_ADVERT;
//	radvert->nd_ra_code  = 0;
//	radvert->nd_ra_cksum = 0;
//
//	radvert->nd_ra_curhoplimit	= 64;
//	radvert->nd_ra_flags_reserved	= (ND_RA_FLAG_MANAGED | ND_RA_FLAG_RTPREF_HIGH);
//	radvert->nd_ra_router_lifetime	 =  htons(60);
//	radvert->nd_ra_reachable  = htonl(60);
//	radvert->nd_ra_retransmit = htonl(60);
//	struct nd_opt_prefix_info *pinfo = &ra.px;
//	pinfo->nd_opt_pi_type	     = ND_OPT_PREFIX_INFORMATION;
//	pinfo->nd_opt_pi_len	     = 4;
//	pinfo->nd_opt_pi_prefix_len  = 64;
//	pinfo->nd_opt_pi_flags_reserved  = (ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO);
//	pinfo->nd_opt_pi_valid_time	= 0xffffffff;
//	pinfo->nd_opt_pi_preferred_time = 0xffffffff;
//	pinfo->nd_opt_pi_reserved2	= 0;
//	ICOPY(&prefix,&pinfo->nd_opt_pi_prefix);
//
//	struct nd_opt_mtu *mtu = &ra.mtu;
//	mtu->nd_opt_mtu_type     = ND_OPT_MTU;
//	mtu->nd_opt_mtu_len      = 1;
//	mtu->nd_opt_mtu_reserved = 0; 
//	mtu->nd_opt_mtu_mtu      = htonl(1500);
//	
//	struct nd_opt_lla *lla = &ra.lla;
//	int optlen = sizeof(struct nd_opt_hdr) + ETHER_ADDR_LEN;
//	optlen = (optlen + 7) & ~7;
//	lla->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
//	lla->nd_opt_len = optlen >> 3;;
//	ECOPY(cujo_global.mac_em1,lla->mac);
//	
//	struct mbuf *m = _makembuf(&ra,sizeof(ra));
//	if (!m) {
//	        _E("failed to create mbuf");
//	        return;
//	}
//	SET_TAG(m,tag);
//	struct nd_router_advert *ckra = (struct nd_router_advert *) (mtod(m, u_char *) + _EIP6);
//	ckra->nd_ra_cksum = _in6_cksum(m, IPPROTO_ICMPV6, _EIP6, sizeof(ra) - _EIP6);
//	_output_em1(m);
//}
