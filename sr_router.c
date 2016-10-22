/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h> 
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */
    
    /* Error checking: the minimum length of ethernet frame */
    /*if ( len < sizeof(sr_ethernet_hdr_t) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return;
    }*/

    uint16_t frametype = ethertype(packet);
    /* if the packet is arp packet */
    if (frametype == ethertype_arp){
      sr_handle_arppacket(sr, packet, len, interface);
    }

    /* if the packet is ip packet */
    if (frametype == ethertype_ip){
      sr_handle_ippacket(sr, packet, len, interface);
    }
}/* end sr_ForwardPacket */



int sr_handle_arppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

    /* Error checking: the minimum length of ARP packet */   
    /*if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return -1;
    }*/

    /* set up header */
    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    struct sr_if* if_list = NULL;
    struct sr_arpreq* arpreq_temp = NULL;
    struct sr_packet* packet_temp = NULL;

    /* receive Interface information, and check whether the message is to me */
    if ((if_list = sr_get_interface(sr, interface)) == 0) {
      fprintf(stderr , "** Error: Interface problem \n");
      return -1;
    }

    /* if the ARP packet is not for me, just ignore this packet, return -1 */
    if (if_list->ip != arp_hdr->ar_tip) {
      fprintf(stderr , "** Ingore: the ARP packet is not for us \n"); 
      return -1;
    }


    /* if this is an arp reply */
    if (arp_hdr->ar_op == arp_op_reply){

      /* Cache the arp reply, go through my request queue */
      arpreq_temp = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

      /* send outstanding packets */
      if (arpreq_temp != NULL){

        packet_temp = arpreq_temp->packets;

        while (1){

          /* substitute Request Queue packet's information with ARP Reply information */

          /* set up header */
          sr_ethernet_hdr_t *buf_hdr = (sr_ethernet_hdr_t *)(packet_temp->buf);
          sr_ip_hdr_t *buf_iphdr = (sr_ip_hdr_t *)(packet_temp->buf + sizeof(sr_ethernet_hdr_t));

          /* recheck interface */
          if_list = sr_get_interface(sr, packet_temp->iface);

          memcpy(buf_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          memcpy(buf_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);
          buf_iphdr->ip_src = if_list->ip;
          buf_iphdr->ip_ttl--;
          buf_iphdr->ip_sum = buf_iphdr->ip_sum >> 16;

          buf_iphdr->ip_sum = cksum(buf_iphdr, sizeof(sr_ip_hdr_t));

          sr_send_packet(sr, packet_temp->buf, packet_temp->len, packet_temp->iface);

          if (packet_temp->next == NULL){
            break;
          }

          packet_temp = packet_temp->next; 
        }

        sr_arpreq_destroy(&(sr->cache), arpreq_temp);
      }
      
    }

    /* if this is an arp request */
    else{

      /* Construct an ARP Reply and Send it back */

      /* set arp header */ 
      arp_hdr->ar_tip = arp_hdr->ar_sip;
      arp_hdr->ar_sip = if_list->ip;
      arp_hdr->ar_op = arp_op_reply;
      memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_sha, if_list->addr, ETHER_ADDR_LEN);

      /* set ethernet header */
      memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);


      sr_send_packet(sr, packet, len, interface); 
      
    }
  return 0;
}



int sr_handle_ippacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

    /* Error checking: the minimum length of IP packet */
    /*if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return -1;
    }*/

    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    struct sr_if* if_list = NULL;

    /* Error checking: whether the IP packet has time out, 
    and if it is time out, send an ICMP message to sources IP*/
    if (ip_hdr->ip_ttl <= 1){
      fprintf(stderr , "** Error: ippacket time out\n");

      /* Time exceeded (type 11, code 0) */
      sr_handle_unreachable(sr, packet, interface, 11, 0);
    }

    /* Error checking: using checksum to check whether there is error bits */
    /*if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff){
      fprintf(stderr , "** Error: ippacket cksum fatal\n");
      return -1;
    }*/

    /* receive Interface List, and check whether the message is to me */
    if ((if_list = sr_get_interface(sr, interface)) == 0) {
      return -1;
    }

    /* If the packet is for me */
    if (ip_hdr->ip_dst == if_list->ip){
      
      /* If the packet is ICMP */
      if (ip_hdr->ip_p == ip_protocol_icmp){

        /* Sanity-check */
        /*if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
        sizeof(sr_icmp_hdr_t) ){
          fprintf(stderr , "** Error: packet is wayy to short \n");
          return -1;
        }*/

        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)(packet
         + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      
        /* Error checking: using checksum to check whether there is error bits */
        /*if (cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)) != 0xffff){
          fprintf(stderr , "** Error: Echo reply cksum fatal\n");
          return -1;
        }*/

        /* If it is ICMP echo req, send echo reply */
        if (icmp_hdr->icmp_type == 0x0008){

          /* Create a copy */

          uint8_t* new_packet;
          new_packet = sr_copy_packet(packet, len);

          /* Headers */

          sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t *)(new_packet);
          sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
          sr_icmp_hdr_t* new_icmp_hrd = (sr_icmp_hdr_t *)(new_packet 
            + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

          /* Using Routing Table to Recheck */
          struct sr_rt* rtable;
          rtable = sr_helper_rtable(sr, ip_hdr->ip_src);

          if (rtable->gw.s_addr){

            /* Update Interface */
            if_list = sr_get_interface(sr, rtable->interface);

            /* Set up IP Header */
            new_ip_hdr->ip_ttl = 0xff;
            new_ip_hdr->ip_p = ip_protocol_icmp;
            new_ip_hdr->ip_src = if_list->ip;
            new_ip_hdr->ip_dst = rtable->dest.s_addr;

            new_ip_hdr->ip_sum = new_ip_hdr->ip_sum >> 16;
            new_ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      
            /* Set up ICMP Header */
            new_icmp_hrd->icmp_type = 0x0000;
            new_icmp_hrd->icmp_sum = new_icmp_hrd->icmp_sum >> 16;
            new_icmp_hrd->icmp_sum = cksum(new_icmp_hrd, sizeof(sr_icmp_hdr_t));

            /* Check Cache */
            struct sr_arpentry * entry;
            entry = sr_arpcache_lookup(&(sr->cache), rtable->gw.s_addr);

            /* Hit */
            if (entry != NULL){
              
              /* Set up Ethernet Header */
              memcpy(new_e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
              memcpy(new_e_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);

              /* send icmp echo reply packet */
              /*
              printf("Send packet:\n");
              print_hdrs(new_packet, len);
              */
              sr_send_packet(sr, new_packet, len, rtable->interface);
            }

            /* Miss */
            else{
              uint8_t *arp_packet = sr_create_arppacket(if_list->addr, if_list->ip, rtable->gw.s_addr);
              sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), rtable->interface);
              sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, new_packet, len, rtable->interface);
            }
         
          }

          free(new_packet);
        }
      }


      /* if it is TCP/UDP, send ICMP port unreachable */
      else if (ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p == 0x0017){
        
        /* Sanity-check */
        /*if ( len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)){
          fprintf(stderr , "** Error: packet is wayy to short \n");
          return -1;
        }*/
        /* Port unreachable (type 3, code 3) */
        sr_handle_unreachable(sr, packet, interface, 3, 3);
      }

    }

    /* if the packet is not for me */
    else{

      /* checking routing table, perform LPM */
      struct sr_rt* rtable;
      rtable = sr_helper_rtable(sr, ip_hdr->ip_dst);

          /* if not match, provide ICMP net unreachable */
          if (rtable == NULL){

            /* Destination net unreachable (type 3, code 0) */
            sr_handle_unreachable(sr, packet, interface, 3, 0);
          }


          /* if match, check ARP cache */
          else{

            struct sr_arpentry* entry;

            /* if Hit, Send */
            if ((entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst)) != NULL){

              /* get new interface */
              if_list = sr_get_interface(sr, rtable->interface);

              /* setup Ip Header */
              ip_hdr->ip_ttl--;
              ip_hdr->ip_sum = ip_hdr->ip_sum >> 16;
              ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

              /* set up Etherent header */
              memcpy(e_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);
              memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

              sr_send_packet(sr, packet, len, if_list->name); 
              free(entry);

            }

            /*if Miss, send ARP request,  Resent > 5, ICMP host unreachable */
            else{

              uint8_t *arp_packet = sr_create_arppacket(if_list->addr, if_list->ip, rtable->gw.s_addr);
              sr_send_packet(sr, arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr), rtable->interface);
              
              sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, packet, len, rtable->interface);
              free(arp_packet);
            }
            free(entry);
          }

    free(rtable);
    }

  return 0;    
}

/* create an new packet using incoming packet */
uint8_t* sr_copy_packet(uint8_t* packet, unsigned int len){

  uint8_t * new_packet = (uint8_t *)malloc(len);
  memcpy(new_packet, packet, len);

  return new_packet;
}
/* Handle Unreachable Case */
void sr_handle_unreachable(struct sr_instance* sr,
            uint8_t * packet,
            char* interface,
            uint8_t icmp_type,
            uint8_t icmp_code){

  /* init length */
  unsigned int total_len = sizeof(sr_ethernet_hdr_t)
   + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

  /* malloc new space for the new packet and copy the information from an IP to it */
  uint8_t * new_packet = (uint8_t *)malloc(total_len);
  memcpy(new_packet, packet, sizeof(sr_ethernet_hdr_t)
   + sizeof(sr_ip_hdr_t));

  /*set up all the header*/
  sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t *)(new_packet);
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* new_icmp_hrd_t3 = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t)
   + sizeof(sr_ip_hdr_t));

  /* Check interface */
  struct sr_if* if_list;
  if_list = sr_get_interface(sr, interface);

  /* set up ethernet necessary information */
  new_e_hdr->ether_type = ethertype_ip;
  memcpy(new_e_hdr->ether_dhost, new_e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_e_hdr->ether_shost, if_list->addr, ETHER_ADDR_LEN);

  /* set up ip necessary information */

  new_ip_hdr->ip_dst = new_ip_hdr->ip_src;
  new_ip_hdr->ip_src = if_list->ip;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_ttl = 0xff;  
  new_ip_hdr->ip_sum = new_ip_hdr->ip_sum >> 16;

  /* make a ip checksum */
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t)); 

  /* set up icmp necessary information */
  new_icmp_hrd_t3->icmp_type = icmp_type;
  new_icmp_hrd_t3->icmp_code = icmp_code;
  memcpy(new_icmp_hrd_t3->data, packet + sizeof(struct sr_ethernet_hdr), ICMP_DATA_SIZE);

  new_icmp_hrd_t3->icmp_sum = new_icmp_hrd_t3->icmp_sum >> 16;
  new_icmp_hrd_t3->icmp_sum = cksum(new_icmp_hrd_t3, sizeof(sr_icmp_t3_hdr_t)); 

  /* send ICMP out */
  sr_send_packet(sr, new_packet, total_len, interface);
  free(new_packet);
  
}

/* routing table helper, to get the mask number in order to provide LPM */
struct sr_rt* sr_helper_rtable(struct sr_instance* sr, uint32_t ip){
 
  uint32_t max_mask = 0;
  struct sr_rt* rtable;
  struct sr_rt* rtable_temp = NULL;

  rtable = sr->routing_table;
  
  while (1){
    if ((rtable->mask.s_addr & ip) == rtable->dest.s_addr){

      if (max_mask == 0){
        max_mask = rtable->mask.s_addr;
        rtable_temp = rtable;
      }

      else if (rtable->mask.s_addr > max_mask){
        max_mask = rtable->mask.s_addr;
        rtable_temp = rtable;
      } 
    }

    if (rtable->next == NULL){
      break;
    }

    rtable = rtable->next;

  }
  

  return rtable_temp;

}

