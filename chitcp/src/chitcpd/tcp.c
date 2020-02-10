/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  Implementation of the TCP protocol.
 *
 *  chiTCP follows a state machine approach to implementing TCP.
 *  This means that there is a handler function for each of
 *  the TCP states (CLOSED, LISTEN, SYN_RCVD, etc.). If an
 *  event (e.g., a packet arrives) while the connection is
 *  in a specific state (e.g., ESTABLISHED), then the handler
 *  function for that state is called, along with information
 *  about the event that just happened.
 *
 *  Each handler function has the following prototype:
 *
 *  int f(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event);
 *
 *  si is a pointer to the chiTCP server info. The functions in
 *       this file will not have to access the data in the server info,
 *       but this pointer is needed to call other functions.
 *
 *  entry is a pointer to the socket entry for the connection that
 *          is being handled. The socket entry contains the actual TCP
 *          data (variables, buffers, etc.), which can be extracted
 *          like this:
 *
 *            tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
 *
 *          Other than that, no other fields in "entry" should be read
 *          or modified.
 *
 *  event is the event that has caused the TCP thread to wake up. The
 *          list of possible events corresponds roughly to the ones
 *          specified in http://tools.ietf.org/html/rfc793#section-3.9.
 *          They are:
 *
 *            APPLICATION_CONNECT: Application has called socket_connect()
 *            and a three-way handshake must be initiated.
 *
 *            APPLICATION_SEND: Application has called socket_send() and
 *            there is unsent data in the send buffer.
 *
 *            APPLICATION_RECEIVE: Application has called socket_recv() and
 *            any received-and-acked data in the recv buffer will be
 *            collected by the application (up to the maximum specified
 *            when calling socket_recv).
 *
 *            APPLICATION_CLOSE: Application has called socket_close() and
 *            a connection tear-down should be initiated.
 *
 *            PACKET_ARRIVAL: A packet has arrived through the network and
 *            needs to be processed (RFC 793 calls this "SEGMENT ARRIVES")
 *
 *            TIMEOUT: A timeout (e.g., a retransmission timeout) has
 *            happened.
 *
 */

/*
 *  Copyright (c) 2013-2014, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or withsend
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
 *    software withsend specific prior written permission.
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
 *  ARISING IN ANY WAY send OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chitcp/log.h"
#include "chitcp/utils.h"
#include "chitcp/buffer.h"
#include "chitcp/chitcpd.h"
#include "serverinfo.h"
#include "connection.h"
#include "tcp.h"
#include <stdlib.h>
#include <string.h>

#define BASE_RCV_WND 4096


void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */

    tcp_data->RCV_WND = BASE_RCV_WND;

}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);

    /* Cleanup of additional tcp_data_t fields goes here */
}

static int chitcpd_tcp_packet_arrival_handle(serverinfo_t *si, chisocketentry_t *entry)
{
    chilog(DEBUG, "Packet Arrival Handler Reached");
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *packet = NULL;
    tcphdr_t *header = NULL;
    if (tcp_data->pending_packets)
    {
      packet = tcp_data->pending_packets->packet;
      chitcp_packet_list_pop_head(&tcp_data->pending_packets);
    }
    header = TCP_PACKET_HEADER(packet);
    chilog(DEBUG, "1");
    if (entry->tcp_state == CLOSED)
    {
        return 0;
    }
    else if (entry->tcp_state == LISTEN)
    {
        if (header->ack)
        {
            return CHITCP_OK;
        }
        if (header->syn)
        {
              chilog(DEBUG, "2");
            tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
            tcp_data->IRS = SEG_SEQ(packet);
            int iss = rand() * 1000;
            tcp_data->ISS = iss;
            tcp_data->SND_WND = SEG_WND(packet);
            tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
            tcphdr_t *send_header;
            uint8_t payload = 0;
            chitcpd_tcp_packet_create(entry, send_packet, &payload, 1);
            send_header = TCP_PACKET_HEADER(send_packet);
            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
            send_header->seq = chitcp_htonl(iss);
            send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            send_header->win = chitcp_htons(tcp_data->SND_WND);
            send_header->syn = 1;
            send_header->ack = 1;
            chitcpd_send_tcp_packet(si, entry, send_packet);
            // free(send_packet);
            tcp_data->SND_UNA = iss;
            tcp_data->SND_NXT = iss + 1;
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
        }
        else
        {
            return 0;
        }
    }
    else if (entry->tcp_state == SYN_SENT)
    {
        if (header->ack)
        {
            if (SEG_ACK(packet) <= tcp_data->ISS || SEG_ACK(packet) > tcp_data->SND_NXT)
            {
                return CHITCP_OK;
            }
        }
        if (header->syn)
        {
              chilog(DEBUG, "3");
            tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
            tcp_data->IRS = SEG_SEQ(packet);
            tcp_data->SND_WND = SEG_WND(packet);
            if (header->ack)
            {
                tcp_data->SND_UNA = SEG_ACK(packet);
                /* any segments on the retransmission queue which are thereby
                 * acknowledged should be removed */
            }
            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                  chilog(DEBUG, "4");
                tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
                tcphdr_t *send_header;
                uint8_t payload = 0;
                chitcpd_tcp_packet_create(entry, send_packet, &payload, 0);
                send_header = TCP_PACKET_HEADER(send_packet);
                // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
                send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                send_header->ack = 1;
                send_header->win = chitcp_htons(tcp_data->SND_WND);

                chitcpd_send_tcp_packet(si, entry, send_packet);
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                return CHITCP_OK;
            }
            else
            {
                  chilog(DEBUG, "5");
                tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
                tcphdr_t *send_header;
                uint8_t payload = 0;
                chitcpd_tcp_packet_create(entry, send_packet, &payload, 1);
                send_header = TCP_PACKET_HEADER(send_packet);
                // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                send_header->seq = chitcp_htonl(tcp_data->ISS);
                send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                send_header->win = chitcp_htons(tcp_data->SND_WND);
                send_header->syn = 1;
                send_header->ack = 1;
                tcp_data->SND_NXT += 1;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                chitcpd_update_tcp_state(si, entry, SYN_RCVD);
                return CHITCP_OK;

            }
        }
        else
        {
              chilog(DEBUG, "6");
            return CHITCP_OK;
        }
    }
    else  // All other states
    {
    chilog(DEBUG, "7");
        /* Check acceptability */
        bool acceptable;
        if (SEG_LEN(packet) == 0)
        {
            if (tcp_data->RCV_WND == 0)
            {
                acceptable = (SEG_SEQ(packet) == tcp_data->RCV_NXT);
            }
            else
            {
                acceptable = (tcp_data->RCV_NXT <= SEG_SEQ(packet) &&
                              SEG_SEQ(packet) < (tcp_data->RCV_NXT + tcp_data->RCV_WND));
            }
        }
        else  // SEG_LEN > 0
        {
            if (tcp_data->RCV_WND == 0)
            {
                acceptable = false;
            }
            else
            {
                int recv_end = tcp_data->RCV_NXT + tcp_data->RCV_WND;
                int seq_end = SEG_SEQ(packet) + SEG_LEN(packet) - 1;
                acceptable = (tcp_data->RCV_NXT <= SEG_SEQ(packet) && SEG_SEQ(packet) < recv_end) ||
                             (tcp_data->RCV_NXT <= seq_end && seq_end < recv_end);
            }
        }

        if (!acceptable)
        {
            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
            tcphdr_t *send_header;
            uint8_t payload = 0;
            chitcpd_tcp_packet_create(entry, send_packet, &payload, 0);
            send_header = TCP_PACKET_HEADER(send_packet);
            send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
            send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            send_header->win = chitcp_htons(tcp_data->SND_WND);
            send_header->ack = 1;
            chitcpd_send_tcp_packet(si, entry, send_packet);
            // free(send_packet);
            // Any further actions needed to "drop" unacceptable segments as specified in RFC??
            return CHITCP_OK;
        }
        else  // Update TCB variables for acceptable segment
        {
            chilog(DEBUG, "RCV_NXT before packet is %s", tcp_data->RCV_NXT);
            chilog(DEBUG, "RCV_WND before packet is %s", tcp_data->RCV_WND);
            tcp_data->SND_WND = SEG_WND(packet);
            tcp_data->RCV_NXT += SEG_LEN(packet);
            tcp_data->RCV_WND -= SEG_LEN(packet);
            chilog(DEBUG, "RCV_NXT after packet is %s", tcp_data->RCV_NXT);
            chilog(DEBUG, "RCV_WND after packet is %s", tcp_data->RCV_WND);
        }

        if (header->syn)
        {
            /* Should free TCB and return. It must be in the window,
               because we just checked for acceptability above */
               chilog(DEBUG, "SYN is in the window, delete TCB and return");
               memset(tcp_data, 0, sizeof (tcp_data));
               // Flush all segment queues here
               chitcpd_update_tcp_state(si, entry, CLOSED);
               return CHITCP_OK;
        }

        if (!header->ack)
        {
            return CHITCP_OK;
        }
        else  // Checking ACK field
        {
            bool becoming_established = false;
            if (entry->tcp_state == SYN_RCVD)
            {
                chilog(INFO, "Quitting here?");
                chilog(INFO, "SND_UNA is %d, SEG_ACK is %d SND_NXT is %d", tcp_data->SND_UNA, SEG_ACK(packet), tcp_data->SND_NXT);
                if (tcp_data->SND_UNA <= SEG_ACK(packet) && SEG_ACK(packet) <=
                                                                tcp_data->SND_NXT)
                {
                    becoming_established = true;
                    // chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                }
                else
                {
                    chilog(DEBUG, "seg_ack unacceptable, would send reset here if it were supported");
                    return CHITCP_OK;
                }
            }

            if (entry->tcp_state == LAST_ACK)
            {
                /* The only thing that can arrive here is ACK of our FIN.
                   Check that our FIN is acknowledged and if so, close connection */
                 if (tcp_data->SND_UNA < SEG_ACK(packet))
                 {
                     memset(tcp_data, 0, sizeof (tcp_data));
                     chitcpd_update_tcp_state(si, entry, CLOSED);
                     return CHITCP_OK;
                 }
            }
            else if (entry->tcp_state == TIME_WAIT)
            {
                /* The only thing that can arrive here is a retransmission of
                   connection's FIN. Acknowledge it and restart timeout */
                   chilog(DEBUG, "Updating RCV_NXT from retransmitted remote FIN");
                   tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
                   tcphdr_t *send_header;
                   uint8_t payload = 0;
                   chitcpd_tcp_packet_create(entry, send_packet, &payload, 0);
                   send_header = TCP_PACKET_HEADER(send_packet);
                   send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
                   send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                   send_header->win = chitcp_htons(tcp_data->SND_WND);
                   send_header->ack = 1;
                   chitcpd_send_tcp_packet(si, entry, send_packet);

                   // Restart the 2 MSL timeout here

            }
            else
            {
                /* All other possible processing of ACK field at minimum
                   goes through ESTABLISHED processing: */

                // Definitely more to do here after 3-way handshake
                if (tcp_data->SND_UNA < SEG_ACK(packet) &&
                      SEG_ACK(packet) <= tcp_data->SND_NXT)
                {
                    tcp_data->SND_UNA = SEG_ACK(packet);
                    /* Need to remove segments in retransmission queue that
                       are acknowledged as a result of this */
                }
                else if (SEG_ACK(packet) < tcp_data->SND_UNA)
                {
                    // Duplicate, can ignore
                    chilog(DEBUG, "SEG_ACK < SND_UNA: duplicate that we can ignore");
                }
                else if (SEG_ACK(packet) > tcp_data->SND_UNA)
                {
                    // Remote is ACKing something not yet sent; so send an ACK and return
                    chilog(DEBUG, "Remote is ACKing something not yet sent");
                    tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
                    tcphdr_t *send_header;
                    uint8_t payload = 0;
                    chitcpd_tcp_packet_create(entry, send_packet, &payload, 0);
                    send_header = TCP_PACKET_HEADER(send_packet);
                    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
                    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
                    send_header->win = chitcp_htons(tcp_data->SND_WND);
                    send_header->ack = 1;
                    chitcpd_send_tcp_packet(si, entry, send_packet);
                    return CHITCP_OK;
                }

                if (becoming_established)
                {
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                }
                // ....

                /* Additional processing in addition to base required by all above */
                if (entry->tcp_state == FIN_WAIT_1)
                {
                    // If our FIN is now acknowledged, enter FIN_WAIT_2 and continue processing
                    chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
                }
                else if (entry->tcp_state == FIN_WAIT_2)
                {
                    /* If the retransmission queue is empty, the user's CLOSE
                       can be acknowledged, but do not delete TCB */

                }
                else if (entry->tcp_state == CLOSING)
                {
                    /* If the ACK acknowledges our FIN, then enter the TIME_WAIT
                       state, otherwise ignore the segment */
                    // How to know if the ACK acknowledges our FIN specifically?

                }

            }
        }

        // Processing the segment text:
        switch (entry->tcp_state)
        {
            case ESTABLISHED:
            case FIN_WAIT_1:
            case FIN_WAIT_2:
                // ...
                break;

            case CLOSE_WAIT:
            case CLOSING:
            case LAST_ACK:
            case TIME_WAIT:
                // ...
                break;
            default:
                break;
        }

        // Check FIN bit:
        if (header->fin)
        {
            if (entry->tcp_state == CLOSED || entry->tcp_state == LISTEN ||
                entry->tcp_state == SYN_SENT)
            {
                return 0;
            }
            // Signal the user "connection closing"
            // Return any pending RECEIVES with the same message
            tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
            switch (entry->tcp_state)
            {
                case SYN_RCVD:
                case ESTABLISHED:
                    break;
                case FIN_WAIT_1:
                    break;
                case TIME_WAIT:
                    break;
                default: // Do Nothing
                    break;
            }
        }
        //
    }

//   seventh, process the segment text,
//
//     ESTABLISHED STATE
//     FIN-WAIT-1 STATE
//     FIN-WAIT-2 STATE
//
//       Once in the ESTABLISHED state, it is possible to deliver segment
//       text to user RECEIVE buffers.  Text from segments can be moved
//       into buffers until either the buffer is full or the segment is
//       empty.  If the segment empties and carries an PUSH flag, then
//       the user is informed, when the buffer is returned, that a PUSH
//       has been received.
//
//       When the TCP takes responsibility for delivering the data to the
//       user it must also acknowledge the receipt of the data.
//
//       Once the TCP takes responsibility for the data it advances
//       RCV.NXT over the data accepted, and adjusts RCV.WND as
//       apporopriate to the current buffer availability.  The total of
//       RCV.NXT and RCV.WND should not be reduced.
//
//       Please note the window management suggestions in section 3.7.
//
//       Send an acknowledgment of the form:
//
//         <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
//
//       This acknowledgment should be piggybacked on a segment being
//       transmitted if possible without incurring undue delay.
//
//
//     CLOSE-WAIT STATE
//     CLOSING STATE
//     LAST-ACK STATE
//     TIME-WAIT STATE
//
//       This should not occur, since a FIN has been received from the
//       remote side.  Ignore the segment text.

//   eighth, check the FIN bit,
//
//     Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
//     since the SEG.SEQ cannot be validated; drop the segment and
//     return.
//
//     If the FIN bit is set, signal the user "connection closing" and
//     return any pending RECEIVEs with same message, advance RCV.NXT
//     over the FIN, and send an acknowledgment for the FIN.  Note that
//     FIN implies PUSH for any segment text not yet delivered to the
//     user.
//
//       SYN-RECEIVED STATE
//       ESTABLISHED STATE
//
//         Enter the CLOSE-WAIT state.
//
//       FIN-WAIT-1 STATE
//
//         If our FIN has been ACKed (perhaps in this segment), then
//         enter TIME-WAIT, start the time-wait timer, turn off the other
//         timers; otherwise enter the CLOSING state.
//
//       FIN-WAIT-2 STATE
//
//         Enter the TIME-WAIT state.  Start the time-wait timer, turn
//         off the other timers.
//
//       CLOSE-WAIT STATE
//
//         Remain in the CLOSE-WAIT state.
//
//       CLOSING STATE
//
//         Remain in the CLOSING state.
//
//       LAST-ACK STATE
//
//         Remain in the LAST-ACK state.
//
//       TIME-WAIT STATE
//
//         Remain in the TIME-WAIT state.  Restart the 2 MSL time-wait
//         timeout.
//
//   and return.
}

int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    if (event == APPLICATION_CONNECT)
    {

        // Is it possible for some parts of the foreign socket to be unspecififed in a passive OPEN?

        if (entry->actpas_type == SOCKET_PASSIVE)
        {
            chitcpd_update_tcp_state(si, entry, LISTEN);
        }
        else if (entry->actpas_type == SOCKET_ACTIVE)
        {
            // Need to check that foreign socket is unspecified
            // ie, check struct sockaddr_storage remote_addr in chisocketentry??
            // tcp_data_init(si, entry);
            int iss = rand() * 1000;
            tcp_data->ISS = iss;
            tcp_data->SND_UNA = iss;
            tcp_data->SND_NXT = iss + 1;
            tcp_data->RCV_WND = 4096;
            tcp_data->SND_WND = 4096;

            tcp_packet_t *packet = calloc(1, sizeof(tcp_packet_t));
            tcphdr_t *header;
            uint8_t payload = 0;
            chitcpd_tcp_packet_create(entry, packet, &payload, 1);
            header = TCP_PACKET_HEADER(packet);
            header->seq = chitcp_htonl(tcp_data->ISS);
            header->win = chitcp_htons(tcp_data->RCV_WND);
            header->syn = 1;
            chitcpd_send_tcp_packet(si, entry, packet);
            chitcpd_update_tcp_state(si, entry, SYN_SENT);
            return CHITCP_OK;
        }

    }
    else if (event == CLEANUP)
    {
        /* Any additional cleanup goes here */
    }
    else
        chilog(WARNING, "In CLOSED state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_LISTEN(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else
        chilog(WARNING, "In LISTEN state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_RCVD(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
    /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_RCVD state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_SYN_SENT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
    /* Your code goes here */
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_SEND)
    {
        /* Your code goes here */
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
       chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == APPLICATION_RECEIVE)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == APPLICATION_CLOSE)
    {
        /* Your code goes here */
    }
    else if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
       chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);


    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
       chilog(WARNING, "In CLOSING state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_TIME_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    chilog(WARNING, "Running handler for TIME_WAIT. This should not happen.");

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_LAST_ACK(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        /* Your code goes here */
    }
    else if (event == TIMEOUT_RTX)
    {
      /* Your code goes here */
    }
    else
       chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */
