#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
long unsigned xmas=0,poison=0,url=0;
pthread_mutex_t xmasl=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Poisonl=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t BlackListl=PTHREAD_MUTEX_INITIALIZER;
int state;
char* payload;
void sign_handle()
{
    //if the program reaches CTRL-C, destroy all mutex variables
    //report the malicious activity found
    pthread_mutex_destroy(&xmasl);
    pthread_mutex_destroy(&Poisonl);
    pthread_mutex_destroy(&blacklistl);
    printf("\n Intrusion Detection Report: \n"
        " Xmas tree scans: %lu\n "
        " ARP responses (cache poisoning): %lu\n"
        " URL Blacklist violations: %lu\n",
        xmas, poison, url );
}
void Payload(char *payload, int length)
{
    int i;
    for(i=1;i<=length;i++)
    {   //print ascii characters
        if(payload[i]>31 && payload[i]<127)
        {
            printf("%c", payload[i]);
        if(payload[i]==10)
            {
                printf("\n  * ");
            }
        }
    }
}
//the analyse function will be called in dispatch.c
void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose)
{
  //sync verbose
  int state=verbose;
  struct ether_header *head = (struct ether_header *)packet;
  int length=header->len;
/*This was initially printing source and desttination adresses
*/
//   printf("%d\n", head->ether_type);
//   for (i = 0; i < 6; ++i) {
//     printf("%02x", head->ether_shost[i]);
//     if (i < 5) {
//       printf(":");
//     }
// }
//     for (i = 0; i < 6; ++i) {
//     printf("%02x", head->ether_dhost[i]);
//     if (i < 5) {
//         printf(":");
//      }
//  }
 unsigned long headerlenghtlayer2;
 struct ip *head2;
 struct tcphdr *head3;
 struct ether_arp *head2bis;
 u_int tcps, tcpd;
 char ips[INET_ADDRSTRLEN], ipd[INET_ADDRSTRLEN];
  switch(ntohs(head->ether_type))
  {
      case ETHERTYPE_IP:
        //if it is an IP packet
        head2 = (struct ip *) (packet + ETH_HLEN);
        headerlenghtlayer2 = head2->ip_hl*4;
        if(head2->ip_p == IPPROTO_TCP)
        //if it's a TCP packet, set source and destination addresses
        {
            head3 = (struct tcphdr *) (packet + ETH_HLEN + headerlenghtlayer2);
            tcps = ntohs(head3->source);
            tcpd = ntohs(head3->dest);
            inet_ntop(AF_INET, & (head2->ip_src), ips, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, & (head2->ip_dst), ipd, INET_ADDRSTRLEN);
            if(head3->fin && head3-> psh && head3->urg)
              //if all flag sets are set, process it as an XMAS packet
                {
                  pthread_mutex_lock(&xmasl);
                  xmas++;
                  pthread_mutex_lock(&xmasl);
                  if(state)
                  {
                      printf("\n XMas scans(host fingerprinting)");
                  }
                }

            if(ntohs(head3->source) == 80 || ntohs(head3->dest) == 80)
            {
                //check the source and destination ports to look for the traffic of "www.bbc.co.uk"
                //construct payload from ether, ip and tcp headers
                //construct payload length
                payload= (u_char*)(packet + sizeof(head) + sizeof(head2) + sizeof (head3));
                length = ntohs(head2->ip_len)-(sizeof(head) + sizeof (head3));
                char* bbc="www.bbc.co.uk";
                char* package= (char*) (packet+ ETH_HLEN + headerlenghtlayer2 + head3->doff*4);
                if(strstr(package,bbc))
                  {
                      printf("\n");
                      pthread_mutex_lock(&BlackListl);
                      url++;
                      pthread_mutex_lock(&BlackListl);
                      if(state)
                      {
                          printf("\nURL Blacklist Violation");
                      }
                      if(state)
                      {
                          Payload(payload, length);
                      }
                  }
            }

        }
        // printf("%d\n", ntohs(head2->ihl));
        // printf("%d\n", ntohs(head2->version));
        // printf("%d\n", ntohs(head2->tos));
        // printf("%d\n", ntohs(head2->tot_len));
        // printf("%d\n", ntohs(head2->id));
        // printf("%d\n", ntohs(head2->frag_off));
        // printf("%d\n", ntohs(head2->ttl));
        // printf("%d\n", ntohs(head2->protocol));
        // printf("%d\n", ntohs(head2->check));
        // printf("%d\n", ntohl(head2->saddr));
        // printf("%d\n", ntohl(head2->daddr));
        break;
        case ETHERTYPE_ARP:
        //found an ARP packet
        head2bis = (struct ether_arp *) (packet + ETH_HLEN);
        headerlenghtlayer2 = sizeof(struct ether_arp);
        if(head2bis->arp_op == htons (ARPOP_REPLY))
        {
            //if it encounters multiple replies
            // it has to be processed as ARP poisoning
            printf("\n");
            pthread_mutex_lock(&Poisonl);
            poison++;
            pthread_mutex_unlock(&Poisonl);
            if(state)
            {
                printf("\nARP responses (cache poisoning)");
            }
        }

        break;
  }


  head3 = (struct tcphdr *) (packet + ETH_HLEN + headerlenghtlayer2);
  //printf("%d\n", ntohs(head3->source));
  //printf("%d\n", ntohs(head3->dest));
  //printf("%d\n", ntohs(head3->seq));
  //printf("%d\n", ntohs(head3->ack_seq));
  //printf("%d\n", head3->res1);
  //printf("%d\n", head3->doff);
  //printf("%d\n", head3->fin);
  //printf("%d\n", head3->syn);
  //printf("%d\n", head3->rst);
  //printf("%d\n", head3->psh);
  //printf("%d\n", head3->ack);
  //printf("%d\n", head3->urg);
  //printf("%d\n", head3->res2);



  }
