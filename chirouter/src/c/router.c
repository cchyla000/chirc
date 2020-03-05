/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When a router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>

#include <string.h>
#include <stdlib.h>

#include "chirouter.h"
#include "protocols/arp.h"
#include "arp.h"
#include "utils.h"
#include "utlist.h"

#define ICMP_ORIGINAL_DATA_SIZE 8
#define ICMP_BASIC_PAYLOAD_SIZE (sizeof(iphdr_t) + ICMP_ORIGINAL_DATA_SIZE)
#define ICMP_BASIC_SIZE (ICMP_HDR_SIZE + ICMP_BASIC_PAYLOAD_SIZE)
#define ICMP_ECHO_SIZE (ICMP_HDR_SIZE + MAX_ECHO_PAYLOAD)
#define IP_VERSION 4
#define IP_IHL ((sizeof(iphdr_t)) / 4)
#define TTL 255
#define ICMPCODE_TIME_EXCEEDED 0

uint8_t* chirouter_create_arp_request(uint8_t *src_mac, uint32_t spa, uint32_t tpa)
{
    uint8_t *raw = calloc(1, sizeof(ethhdr_t) + sizeof(arp_packet_t));
    ethhdr_t *hdr = (ethhdr_t*) raw;
    arp_packet_t *arp = (arp_packet_t*) (raw + sizeof(ethhdr_t));
    memset(hdr->dst, 0xff, ETHER_ADDR_LEN);
    memcpy(hdr->src, src_mac, ETHER_ADDR_LEN);
    hdr->type = htons(ETHERTYPE_ARP);

    arp->hrd = htons(ARP_HRD_ETHERNET);
    arp->pro = htons(ETHERTYPE_IP);
    arp->hln = ETHER_ADDR_LEN;
    arp->pln = IPV4_ADDR_LEN;
    arp->op = htons(ARP_OP_REQUEST);
    memcpy(arp->sha, src_mac, ETHER_ADDR_LEN);
    arp->spa = spa;
    memset(arp->tha, 0xff, ETHER_ADDR_LEN);
    arp->tpa = tpa;

    return raw;

}

/* used for dst unreachable and time exceeded */
int send_icmp_basic(chirouter_ctx_t *ctx, ethernet_frame_t *frame, uint8_t type, uint8_t code)
{
    chilog(DEBUG, "UNREACHABLE RESPONSE WITH CODE: %i", code);
    iphdr_t* ip_hdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    ethhdr_t *hdr = (ethhdr_t*) frame->raw;
    size_t reply_len = sizeof(ethhdr_t) + sizeof(iphdr_t) + ICMP_BASIC_SIZE;
    uint8_t *reply = calloc(1, reply_len);
    icmp_packet_t* reply_icmp = (icmp_packet_t*) (reply + sizeof(ethhdr_t) + sizeof(iphdr_t));
    reply_icmp->type = type;
    reply_icmp->code = code;
    /* this can safely assume the union is time_exceeded because the payload
     * is the only variable being modified and it is in the same location
     * regardless */
    memcpy(reply_icmp->time_exceeded.payload, ip_hdr, ICMP_BASIC_PAYLOAD_SIZE);
    reply_icmp->chksum = cksum(reply_icmp, ICMP_BASIC_SIZE);
    iphdr_t* reply_ip_hdr = (iphdr_t*) (reply + sizeof(ethhdr_t));
    reply_ip_hdr->version = IP_VERSION;
    reply_ip_hdr->ihl = IP_IHL;
    reply_ip_hdr->len = htons(sizeof(iphdr_t) + ICMP_BASIC_SIZE);
    reply_ip_hdr->ttl = TTL;
    reply_ip_hdr->proto = IPPROTO_ICMP;
    reply_ip_hdr->src = frame->in_interface->ip.s_addr;
    reply_ip_hdr->dst = ip_hdr->src;
    reply_ip_hdr->cksum = cksum(reply_ip_hdr, sizeof(iphdr_t));
    ethhdr_t* reply_hdr = (ethhdr_t*) reply;
    reply_hdr->type = htons(ETHERTYPE_IP);
    memcpy(reply_hdr->src, frame->in_interface->mac, ETHER_ADDR_LEN);
    memcpy(reply_hdr->dst, hdr->src, ETHER_ADDR_LEN);
    /* DON'T FORGET ERROR CHECKING */
    chirouter_send_frame(ctx, frame->in_interface, reply, reply_len);
    free(reply);
    return 0;
}

int chirouter_process_ipv4_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    iphdr_t* ip_hdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    ethhdr_t *hdr = (ethhdr_t*) frame->raw;
    uint8_t *reply;
    size_t reply_len;
    icmp_packet_t* reply_icmp;
    iphdr_t* reply_ip_hdr;
    ethhdr_t* reply_hdr;

    /* check if it is directed to the interface that recieved it */
    if (((uint32_t) frame->in_interface->ip.s_addr) == ip_hdr->dst)
    {
        /* check if time to live is 1 */
        if ((ip_hdr->proto) == IPPROTO_ICMP)
        {
            if (ip_hdr->ttl == 1)
            {
                return send_icmp_basic(ctx, frame, ICMPTYPE_TIME_EXCEEDED, ICMPCODE_TIME_EXCEEDED);
            }
            icmp_packet_t* icmp = (icmp_packet_t*) (frame->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));
            if (icmp->type == ICMPTYPE_ECHO_REQUEST)
            {
                reply_len = frame->length;
                reply = calloc(1, reply_len);
                reply_icmp = (icmp_packet_t*) (reply + sizeof(ethhdr_t) + sizeof(iphdr_t));
                reply_icmp->type = ICMPTYPE_ECHO_REPLY;
                memcpy(reply_icmp->echo.payload, icmp->echo.payload, sizeof(icmp->echo.payload));
                reply_icmp->echo.identifier = icmp->echo.identifier;
                reply_icmp->echo.seq_num = icmp->echo.seq_num;
                reply_icmp->chksum = cksum(reply_icmp, ICMP_ECHO_SIZE);
                reply_ip_hdr = (iphdr_t*) (reply + sizeof(ethhdr_t));
                reply_ip_hdr->version = IP_VERSION;
                reply_ip_hdr->ihl = IP_IHL;
                reply_ip_hdr->tos = ip_hdr->tos;
                reply_ip_hdr->len = ip_hdr->len;
                reply_ip_hdr->id = ip_hdr->id;
                reply_ip_hdr->off = ip_hdr->off;
                reply_ip_hdr->ttl = ip_hdr->ttl;
                reply_ip_hdr->proto = ip_hdr->proto;
                reply_ip_hdr->src = ip_hdr->dst;
                reply_ip_hdr->dst = ip_hdr->src;
                reply_ip_hdr->cksum = cksum(reply_ip_hdr, sizeof(iphdr_t));
                reply_hdr = (ethhdr_t*) reply;
                reply_hdr->type = htons(ETHERTYPE_IP);
                memcpy(reply_hdr->src, hdr->dst, ETHER_ADDR_LEN);
                memcpy(reply_hdr->dst, hdr->src, ETHER_ADDR_LEN);
                chirouter_send_frame(ctx, frame->in_interface, reply, reply_len);
                free(reply);
                return 0;
            }
            else
            {
                return 0;
            }
        }
        else if ((ip_hdr->proto) == IPPROTO_UDP || (ip_hdr->proto) == IPPROTO_TCP)
        {
            return send_icmp_basic(ctx, frame, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_PORT_UNREACHABLE);
        }
        else
        {
            return send_icmp_basic(ctx, frame, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_PROTOCOL_UNREACHABLE);
        }

    }
    /* check if it is directed to another interface on the router */
    bool found_on_router = false;
    chirouter_interface_t *interface = ctx->interfaces;
    for (int i = 0; i < ctx->num_interfaces; i++)
    {
        if (((uint32_t) interface->ip.s_addr) == ip_hdr->dst)
        {
            found_on_router = true;
            break;
        }
        interface++;
    }
    if (found_on_router)
    {
        return send_icmp_basic(ctx, frame, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_NET_UNREACHABLE);
    }
    /* check if ttl is 1 */
    if (ip_hdr->ttl == 1)
    {
        return send_icmp_basic(ctx, frame, ICMPTYPE_TIME_EXCEEDED, ICMPCODE_TIME_EXCEEDED);
    }
    else
    {
         /* Check routing table here */
         int i;
         uint32_t longest_mask = 0;
         chirouter_rtable_entry_t *rtable_entry;
         chirouter_rtable_entry_t *return_entry = NULL;
         for (i=0; i < ctx->num_rtable_entries; i++)
         {
              rtable_entry = &ctx->routing_table[i];
              if ((rtable_entry->dest.s_addr == (rtable_entry->mask.s_addr & ip_hdr->dst))
                   && (rtable_entry->mask.s_addr >= longest_mask))
              {
                  longest_mask = rtable_entry->mask.s_addr;
                  return_entry = rtable_entry;
              }
         }

         if (return_entry == NULL)
         {
              chilog(DEBUG, "No matching entries in routing table");
              return send_icmp_basic(ctx, frame, ICMPTYPE_DEST_UNREACHABLE, ICMPCODE_DEST_NET_UNREACHABLE);
         }

         chirouter_interface_t* interface = return_entry->interface;

         struct in_addr ip_addr;
         ip_addr.s_addr = ip_hdr->dst;

         chirouter_arpcache_entry_t* arpcache_entry;
         pthread_mutex_lock(&(ctx->lock_arp));
         arpcache_entry = chirouter_arp_cache_lookup(ctx, &ip_addr);
         pthread_mutex_unlock(&(ctx->lock_arp));

         if (arpcache_entry == NULL)  // Cache MISS
         {
             chilog(DEBUG, "Cache MISS");
             uint8_t *raw = chirouter_create_arp_request(interface->mac,
                                interface->ip.s_addr, ip_hdr->dst);
             chirouter_send_frame(ctx, interface, raw, sizeof(ethhdr_t) + sizeof(arp_packet_t));
             free(raw);

         }
         else  // Cache HIT
         {
              chilog(DEBUG, "Cache HIT");
              memcpy(hdr->dst, arpcache_entry->mac, ETHER_ADDR_LEN);
              memcpy(hdr->src, interface->mac, ETHER_ADDR_LEN);
              chirouter_send_frame(ctx, interface, frame->raw, frame->length);
         }


    }

    return 0;
}

/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * a router. This function receives the router context for the router that
 * received the frame, and the inbound frame (the ethernet_frame_t struct
 * contains a pointer to the interface where the frame was received).
 * Take into account that the chirouter code will free the frame after this
 * function returns so, if you need to persist a frame (e.g., because you're
 * adding it to a list of withheld frames in the pending ARP request list)
 * you must make a deep copy of the frame.
 *
 * chirouter can manage multiple routers at once, but does so in a single
 * thread. i.e., it is guaranteed that this function is always called
 * sequentially, and that there will not be concurrent calls to this
 * function. If two routers receive Ethernet frames "at the same time",
 * they will be ordered arbitrarily and processed sequentially, not
 * concurrently (and with each call receiving a different router context)
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 *   Note: In the event of a critical error, the entire router will shut down and exit.
 *         You should only return -1 for issues that would prevent the router from
 *         continuing to run normally. Return 1 to indicate that the frame could
 *         not be processed, but that subsequent frames can continue to be processed.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    ethhdr_t *hdr = (ethhdr_t*) frame->raw;
    if (ntohs(hdr->type) == ETHERTYPE_ARP)
    {
        arp_packet_t *arp = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));
        if (ntohs(arp->hrd) == ARP_HRD_ETHERNET)
        {
            if (ntohs(arp->pro) == ETHERTYPE_IP)
            {
                if (arp->tpa == ((uint32_t) frame->in_interface->ip.s_addr))
                {
                    if (ntohs(arp->op) == ARP_OP_REQUEST)
                    {
                        uint32_t tmp_pro_addr;
                        memcpy(arp->tha, arp->sha, ETHER_ADDR_LEN);
                        memcpy(arp->sha, frame->in_interface->mac, ETHER_ADDR_LEN);
                        tmp_pro_addr = arp->spa;
                        arp->spa = arp->tpa;
                        arp->tpa = tmp_pro_addr;
                        arp->op = htons(ARP_OP_REPLY);
                        memcpy(hdr->dst, hdr->src, ETHER_ADDR_LEN);
                        memcpy(hdr->src, frame->in_interface->mac, ETHER_ADDR_LEN);
                        chirouter_send_frame(ctx, frame->in_interface, frame->raw, frame->length);
                    }
                    else if (ntohs(arp->op) == ARP_OP_REPLY)
                    {
                        struct in_addr ip_addr;
                        ip_addr.s_addr = arp->spa;
                        chirouter_arp_cache_add(ctx, &ip_addr, arp->sha);
                    }
                }
            }
        }
    }
    else if (ntohs(hdr->type) == ETHERTYPE_IP)
    {
        return chirouter_process_ipv4_frame(ctx, frame);
    }
}
