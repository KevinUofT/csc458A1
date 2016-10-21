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
    if ( len < sizeof(struct sr_ethernet_hdr) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return -1;
    }

    /* Error checking: using checksum to check whether there is error bits */
    /*if (cksum() )*/

    uint16_t frametype = ethertype(packet);
    if (frametype == ethertype_arp){
      sr_handle_arppacket(sr, packet, len, interface);
    }

    if (frametype == ethertype_ip){
      sr_handle_ippacket(sr, packet, len, interface);
    }
}/* end sr_ForwardPacket */



void sr_handle_arppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* Error checking: the minimum length of ARP packet */
    if ( len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return -1;
    }

    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    

    struct sr_if* if_list_temp = NULL;
    struct sr_arpreq* arpreq_temp = NULL;
    struct sr_arpreq* arpreq_temp2 = NULL;

    /* receive Interface information, and check whether the message is to me */
    if ((if_list_temp = sr_get_interface(sr, interface)) == 0) {
      fprintf(stderr , "** Error: Interface problem \n");
      return -1;
    }

    /* if the ARP packet is not for me, just ignore this packet, return -1 */
    if (if_list_temp->ip != arp_hdr->ar_tip) {
      fprintf(stderr , "** Ingore: the ARP packet is not for us \n"); 
      return -1;
    }


    /* if this is an arp reply */
    if (arp_hdr->ar_op == arp_op_reply){

      /* Cache the arp reply, go through my request queue */
      arpreq_temp = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
      arpreq_temp2 = arpreq_temp;

      /* send outstanding packets */
      if (arpreq_temp != NULL){
        while (1){

          /* substitute ether_dhost with MAC address from ARP Reply */
          sr_ethernet_hdr_t *buf_hdr = (sr_ethernet_hdr_t *)(arpreq_temp->packets->buf);
          memcpy(buf_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          sr_send_packet(sr, arpreq_temp->packets->buf, arpreq_temp->packets->len, arpreq_temp->packets->iface);

          if (arpreq_temp->next == NULL){
            break;
          }

          arpreq_temp = arpreq_temp->next; 
        }

        sr_arpreq_destroy(&(sr->cache), arpreq_temp2);
      }
      
    }

    /* if this is an arp request */
    else{

      /* Construct an ARP Reply and Send it back */
      memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_sha, if_list_temp->addr, ETHER_ADDR_LEN);
      arp_hdr->ar_tip = arp_hdr->ar_sip;
      arp_hdr->ar_sip = if_list_temp->ip;
      memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_shost, if_list_temp->addr, ETHER_ADDR_LEN);

      sr_send_packet(sr, packet, len, interface); 
      
    }

}



void sr_handle_ippacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

    /* Error checking: the minimum length of IP packet */
    if ( len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) ){
        fprintf(stderr , "** Error: packet is wayy to short \n");
        return -1;
    }

    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Error checking: whether the IP packet has time out */
    if (ip_hdr->ip_ttl <= 1){
      fprintf(stderr , "** Error: ippacket time out\n");
      return -1;
    }

    /* Error checking: using checksum to check whether there is error bits */
    if (cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t)) != 0xffff){
      fprintf(stderr , "** Error: ippacket cksum fatal\n");
      return -1;
    }

    uint8_t ip_proto;
    uint8_t temp_ip_store;
    struct sr_if* if_list_temp = NULL;

    /* receive Interface List, and check whether the message is to me */
    if ((if_list_temp = sr_get_interface(sr, interface)) == 0) {
      return -1;
    }

    /* If the packet is for me and it is ICMP */
    if (ip_hdr->ip_dst == if_list_temp->ip){
      ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
      
      if (ip_proto == ip_protocol_icmp){
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      
        /* Error checking: using checksum to check whether there is error bits */
        if (cksum(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), sizeof(sr_icmp_hdr_t)) != 0xffff){
          fprintf(stderr , "** Error: Echo reply cksum fatal\n");
          return -1;
        }

        /* if it is ICMP echo req, send echo reply */
        if (icmp_hdr->icmp_type == 8){

          /*Type 0, Echo Reply*/
          icmp_hdr->icmp_type = 0;


          temp_ip_store = ip_hdr->ip_dst;
          ip_hdr->ip_dst = ip_hdr->ip_src;
          ip_hdr->ip_src = temp_ip_store;
          ip_hdr->ip_ttl = 64;
          memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
          memcpy(e_hdr->ether_shost, if_list_temp->addr, ETHER_ADDR_LEN);
          icmp_hdr->icmp_sum = icmp_hdr->icmp_sum >> 16;

          icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

          sr_send_packet(sr, packet, len, if_list_temp->name); 

        }
      }

      /* if it is TCP/UDP, send ICMP port unreachable */
      else if (ip_proto == 6 || ip_proto == 17){
        
        uint8_t* new_packet = sr_create_icmpt3packet(if_list_temp->addr,
        packet, 3, 3);

        sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t)
         + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface); 

        free(new_packet);
      }

    }

    /* if the packet is not for me */
    else{

      /* checking routing table, perform LPM */
      char table_name[6] = "rtable";
      sr_load_rt(sr, table_name);

      struct sr_rt* rtable = sr->routing_table;
      rtable = sr_helper_rtable(rtable, ip_hdr->ip_dst);

          /* if not match, provide ICMP net unreachable */
          if (rtable == NULL){
            uint8_t* new_packet = sr_create_icmpt3packet(if_list_temp->addr, 
              packet, 3, 0);

            sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t) + 
              sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface); 

            free(new_packet);
          }


          /* if match, check ARP cache */
          else{

            /* if Hit, Send */
            struct sr_arpentry* sr_cache_entry = NULL;
            if ((sr_cache_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst)) != NULL){
              ip_hdr->ip_ttl--;
              memcpy(e_hdr->ether_shost, if_list_temp->addr, ETHER_ADDR_LEN);
              memcpy(e_hdr->ether_dhost, sr_cache_entry->mac, ETHER_ADDR_LEN);

              sr_send_packet(sr, packet, len, if_list_temp->name); 
              free(sr_cache_entry);


            }

            /*if Miss, send ARP request,  Resent > 5, ICMP host unreachable */
            else{

              uint8_t* new_packet = sr_create_arppacket(if_list_temp->addr, 
              if_list_temp->addr, if_list_temp->ip, sr_cache_entry->ip);

              sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
              
              sr_arpcache_queuereq(&(sr->cache), rtable->gw.s_addr, new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), rtable->interface); 
              free(new_packet);


            }
            

          }

    }

    
}


/* create a new Type 3 icmp packet */
uint8_t* sr_create_icmpt3packet(uint8_t * MAC_src,
            uint8_t * packet,
            uint8_t icmp_type,
            uint8_t icmp_code){

  /* init length */
  unsigned int total_len = sizeof(sr_ethernet_hdr_t)
   + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

  unsigned int ip_len = sizeof(sr_ethernet_hdr_t)
   + sizeof(sr_ip_hdr_t);

  /* malloc new space for the new packet and copy the information from an IP to it */
  uint8_t * new_packet = (uint8_t *)malloc(total_len);
  memcpy(new_packet, packet, ip_len);

  /*set up all the header*/
  sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t *)(new_packet);
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* new_icmp_hrd_t3 = (sr_icmp_t3_hdr_t *)(new_packet + ip_len);

  sr_ethernet_hdr_t *p_e_hdr = (sr_ethernet_hdr_t *)(packet);
  sr_ip_hdr_t *p_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* set up ethernet necessary information */
  new_e_hdr->ether_type = ethertype_ip;
  memcpy(new_e_hdr->ether_dhost, p_e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_e_hdr->ether_shost, MAC_src, ETHER_ADDR_LEN);

  /* set up ip necessary information */

  new_ip_hdr->ip_dst = p_ip_hdr->ip_src;
  new_ip_hdr->ip_src = p_ip_hdr->ip_dst;
  new_ip_hdr->ip_p = ip_protocol_icmp;
  new_ip_hdr->ip_ttl = 64;  
  new_ip_hdr->ip_sum = new_ip_hdr->ip_sum >> 16;

  /* make a ip checksum */
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t)); 

  /* set up icmp necessary information */
  new_icmp_hrd_t3->icmp_type = icmp_type;
  new_icmp_hrd_t3->icmp_code = icmp_code;
  new_icmp_hrd_t3->icmp_sum = new_icmp_hrd_t3->icmp_sum >> 16;
  
  new_icmp_hrd_t3->icmp_sum = cksum(new_icmp_hrd_t3, sizeof(sr_icmp_t3_hdr_t)); 

  printf("successful create icmpt3 packet\n");
  return new_packet;
}

/* routing table helper, to get the mask number in order to provide LPM */
struct sr_rt* sr_helper_rtable(struct sr_rt* rtable, uint32_t ip){
 
  uint32_t max_mask = 0;
  struct sr_rt* rtable_temp = NULL;

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
