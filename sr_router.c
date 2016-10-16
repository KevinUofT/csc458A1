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
    //if (cksum() )

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

 
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);

    struct sr_if* if_list_temp = NULL;
    struct sr_arpreq* arpreq_temp = NULL;
    struct sr_arpreq* arpreq_temp2 = NULL;

    /* receive Interface information, and check whether the message is to me */
    if ((if_list_temp = sr_get_interface(sr, interface)) == 0) {
      return -1;
    }

    /* if the ARP packet is not for me, just ignore this packet, return -1 */
    if (if_list_temp->ip != arp_hdr->ar_tip) { 
      return -1;
    }


    /* if this is an arp reply */
    if (arp_hdr->ar_op == arp_op_reply){

      /* Cache the arp reply, go through my request queue */
      arpreq_temp = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha[ETHER_ADDR_LEN], arp_hdr->ar_sip);
      arpreq_temp2 = arpreq_temp;

      /* send outstanding packets */
      if (arpreq_temp != NULL){
        while (arpreq_temp != NULL){

          /* substitute ether_dhost with MAC address from ARP Reply */
          strncpy(arpreq_temp->packets->buf->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          sr_send_packet(sr, arpreq_temp->packets->buf, len, interface);

          arpreq_temp = arpreq_temp->next; 
        }

        sr_arpreq_destroy(&(sr->cache), arpreq_temp2);
      }
      
    }

    /* if this is an arp request */
    else{

      /* Construct an ARP Reply and Send it back */
      strncpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      strncpy(arp_hdr->ar_sha, if_list_temp->addr, ETHER_ADDR_LEN);
      arp_hdr->ar_tip = arp_hdr->ar_sip;
      arp_hdr->ar_sip = if_list_temp->ip;
      strncpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      strncpy(e_hdr->ether_shost, if_list_temp->addr, ETHER_ADDR_LEN);

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

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *e_hdr = (sr_ethernet_hdr_t *)(packet);

    /* Error checking: whether the IP packet has time out */

    /* Error checking: using checksum to check whether there is error bits */
    //if (cksum() )


    uint8_t ip_proto = 0;
    uint8_t temp_ip_store = 0;
    struct sr_if* if_list_temp = NULL;

    /* receive Interface List, and check whether the message is to me */
    if ((if_list_temp = sr_get_interface(sr, interface)) == 0) {
      return -1;
    }

    /* If the packet is for me and it is ICMP */
    if (ip_hdr->ip_dst == if_list_temp->ip){
      ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
      
      if (ip_proto == ip_protocol_icmp){
        sr_icmp_hdr_t* icmp_hrd = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      }

      /* if it is ICMP echo req, send echo reply */
      if (icmp_hdr->icmp_type == 8){
        icmp_hrd->icmp_type = 0;
        temp_ip_store = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = temp_ip_store;
        ip_hdr->ip_ttl--;
        strncpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
        strncpy(e_hdr->ether_shost, if_list_temp->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, packet, len, interface); 

      }

      /* if it is TCP/UDP, send ICMP port unreachable */
      else if (ip_proto == 6 || ip_proto == 17){
        sr_icmp_t3_hdr_t* icmp_hrd_t3 = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        (struct sr_icmp_t3_hdr_t* )malloc( sizeof(sr_icmp_t3_hdr))


        icmp_hrd_t3->icmp_type = 3;
        icmp_hrd_t3->icmp_code = 3;
        temp_ip_store = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = temp_ip_store;
        ip_hdr->ip_ttl--;
        strncpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
        strncpy(e_hdr->ether_shost, if_list_temp->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, packet, len, interface); 

      }

    }

    /* if the packet is not for me */
    else{

      /* checking routing table, perform LPM */


      /* if not match, provide ICMP net unreachable */



      /* if match, check ARP cache */


      /* if Hit, Send */



      /*if Miss, send ARP request,  Resent > 5, ICMP host unreachable */











    }






    
}

