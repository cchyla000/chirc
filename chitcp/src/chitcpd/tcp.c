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




void tcp_data_init(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;

    tcp_data->pending_packets = NULL;
    pthread_mutex_init(&tcp_data->lock_pending_packets, NULL);
    pthread_cond_init(&tcp_data->cv_pending_packets, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */

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
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *packet = NULL;
    tcphdr_t *header = NULL;
    if (tcp_data->pending_packets)
    {
      packet = tcp_data->pending_packets->packet;
      chitcp_packet_list_pop_head(&tcp_data->pending_packets);
    }
    header = TCP_PACKET_HEADER(packet);
//   SEGMENT ARRIVES
//   If the state is CLOSED (i.e., TCB does not exist) then
//
//     all data in the incoming segment is discarded.  An incoming
//     segment containing a RST is discarded.  An incoming segment not
//     containing a RST causes a RST to be sent in response.  The
//     acknowledgment and sequence field values are selected to make the
//     reset sequence acceptable to the TCP that sent the offending
//     segment.
//
//     If the ACK bit is off, sequence number zero is used,
//
//       <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
//
//     If the ACK bit is on,
//
//       <SEQ=SEG.ACK><CTL=RST>
//
//     Return.
//
//   If the state is LISTEN then
    if (entry->tcp_state == CLOSED)
    {

    }
    else if (entry->tcp_state == LISTEN)
    {
        if (header->ack)
        {
            return CHITCP_OK;
        }
        if (header->syn)
        {
            tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
            tcp_data->IRS = SEG_SEQ(packet);
            int iss = rand();
            tcp_data->ISS = iss;
            tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
            tcphdr_t *send_header;
            chitcpd_tcp_packet_create(entry, packet, NULL, 0);
            send_header = TCP_PACKET_HEADER(packet);
            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
            send_header->seq = iss
            send_header->ack_seq = tcp_data->RCV_NEXT
            send_header->syn = 1;
            send_header->ack = 1;
            chitcpd_send_tcp_packet(si, entry, send_packet);
            free(send_packet);
            tcp_data->SND_UNA = iss;
            tcp_data->SND_NXT = iss + 1;
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
        }
        else
        {
            return 0;
        }
    }
//
//     first check for an RST
//
//       An incoming RST should be ignored.  Return.
//
//     second check for an ACK
//
//       Any acknowledgment is bad if it arrives on a connection still in
//       the LISTEN state.  An acceptable reset segment should be formed
//       for any arriving ACK-bearing segment.  The RST should be
//       formatted as follows:
//
//         <SEQ=SEG.ACK><CTL=RST>
//
//       Return.
//
//     third check for a SYN
//
//       If the SYN bit is set, check the security.  If the
//       security/compartment on the incoming segment does not exactly
//       match the security/compartment in the TCB then send a reset and
//       return.
//
//         <SEQ=SEG.ACK><CTL=RST>
//
//       If the SEG.PRC is greater than the TCB.PRC then if allowed by
//       the user and the system set TCB.PRC<-SEG.PRC, if not allowed
//       send a reset and return.
//
//         <SEQ=SEG.ACK><CTL=RST>
//
//       If the SEG.PRC is less than the TCB.PRC then continue.
//
//       Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
//       control or text should be queued for processing later.  ISS
//       should be selected and a SYN segment sent of the form:
//
//         <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
//
//       SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
//       state should be changed to SYN-RECEIVED.  Note that any other
//       incoming control or data (combined with SYN) will be processed
//       in the SYN-RECEIVED state, but processing of SYN and ACK should
//       not be repeated.  If the listen was not fully specified (i.e.,
//       the foreign socket was not fully specified), then the
//       unspecified fields should be filled in now.
//
//     fourth other text or control
//
//       Any other control or text-bearing segment (not containing SYN)
//       must have an ACK and thus would be discarded by the ACK
//       processing.  An incoming RST segment could not be valid, since
//       it could not have been sent in response to anything sent by this
//       incarnation of the connection.  So you are unlikely to get here,
//       but if you do, drop the segment, and return.

    if (entry->tcp_state == SYN_SENT)
    {
        if (header->ack)
        {
            if SEG_ACK(packet) <= tcp_data->ISS || SEG_ACK(packet) > tcp_data->SEND_NXT
            {
                return CHITCP_OK;
            }
        }
        if (header->syn)
        {
            tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
            tcp_data->IRS = SEG_SEQ(packet);
            if (header->ack)
            {
                tcp_data->SND_UNA = SEG_ACK(packet);
                /* any segments on the retransmission queue which are thereby
                 * acknowledged should be removed */
            }
            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
                tcphdr_t *send_header;
                chitcpd_tcp_packet_create(entry, packet, NULL, 0);
                send_header = TCP_PACKET_HEADER(packet);
                // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                send_header->seq = tcp_data->SND_NXT
                send_header->ack_seq = tcp_data->RCV_NEXT
                send_header->ack = 1;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                free(send_packet);
            }
            else
            {
                chitcpd_update_tcp_state(si, entry, SYN-RECEIVED);
                tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
                tcphdr_t *send_header;
                chitcpd_tcp_packet_create(entry, packet, NULL, 0);
                send_header = TCP_PACKET_HEADER(packet);
                // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
                send_header->seq = tcp_data->ISS
                send_header->ack_seq = tcp_data->RCV_NEXT
                send_header->syn = 1;
                send_header->ack = 1;
                chitcpd_send_tcp_packet(si, entry, send_packet);
                free(send_packet);
            }
        }
        else
        {
            return CHITCP_OK;
        }
    }
//   If the state is SYN-SENT then
//
//     first check the ACK bit
//
//       If the ACK bit is set
//
//         If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
//         the RST bit is set, if so drop the segment and return)
//
//           <SEQ=SEG.ACK><CTL=RST>
//
//         and discard the segment.  Return.
//
//         If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.
//
//     second check the RST bit
//
//       If the RST bit is set
//
//         If the ACK was acceptable then signal the user "error:
//         connection reset", drop the segment, enter CLOSED state,
//         delete TCB, and return.  Otherwise (no ACK) drop the segment
//         and return.
//
//     third check the security and precedence
//
//       If the security/compartment in the segment does not exactly
//       match the security/compartment in the TCB, send a reset
//
//         If there is an ACK
//
//           <SEQ=SEG.ACK><CTL=RST>
//
//         Otherwise
//
//           <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
//
//       If there is an ACK
//
//         The precedence in the segment must match the precedence in the
//         TCB, if not, send a reset
//
//           <SEQ=SEG.ACK><CTL=RST>
//
//       If there is no ACK
//
//         If the precedence in the segment is higher than the precedence
//         in the TCB then if allowed by the user and the system raise
//         the precedence in the TCB to that in the segment, if not
//         allowed to raise the prec then send a reset.
//
//           <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
//
//         If the precedence in the segment is lower than the precedence
//         in the TCB continue.
//
//       If a reset was sent, discard the segment and return.
//
//     fourth check the SYN bit
//
//       This step should be reached only if the ACK is ok, or there is
//       no ACK, and it the segment did not contain a RST.
//
//       If the SYN bit is on and the security/compartment and precedence
//       are acceptable then, RCV.NXT is set to SEG.SEQ+1, IRS is set to
//       SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
//       is an ACK), and any segments on the retransmission queue which
//       are thereby acknowledged should be removed.
//
//       If SND.UNA > ISS (our SYN has been ACKed), change the connection
//       state to ESTABLISHED, form an ACK segment
//
//         <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
//
//       and send it.  Data or controls which were queued for
//       transmission may be included.  If there are other controls or
//       text in the segment then continue processing at the sixth step
//       below where the URG bit is checked, otherwise return.
//
//       Otherwise enter SYN-RECEIVED, form a SYN,ACK segment
//
//         <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
//
//       and send it.  If there are other controls or text in the
//       segment, queue them for processing after the ESTABLISHED state
//       has been reached, return.
//
//     fifth, if neither of the SYN or RST bits is set then drop the
//     segment and return.
//
//   Otherwise,
//
//   first check sequence number
//
//     SYN-RECEIVED STATE
//     ESTABLISHED STATE
//     FIN-WAIT-1 STATE
//     FIN-WAIT-2 STATE
//     CLOSE-WAIT STATE
//     CLOSING STATE
//     LAST-ACK STATE
//     TIME-WAIT STATE
//
//       Segments are processed in sequence.  Initial tests on arrival
//       are used to discard old duplicates, but further processing is
//       done in SEG.SEQ order.  If a segment's contents straddle the
//       boundary between old and new, only the new parts should be
//       processed.
//
//       There are four cases for the acceptability test for an incoming
//       segment:
//
//       Segment Receive  Test
//       Length  Window
//       ------- -------  -------------------------------------------
//
//          0       0     SEG.SEQ = RCV.NXT
//
//          0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//
//         >0       0     not acceptable
//
//         >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//                     or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
//
//       If the RCV.WND is zero, no segments will be acceptable, but
//       special allowance should be made to accept valid ACKs, URGs and
//       RSTs.
//
//       If an incoming segment is not acceptable, an acknowledgment
//       should be sent in reply (unless the RST bit is set, if so drop
//       the segment and return):
//
//         <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
//
//       After sending the acknowledgment, drop the unacceptable segment
//       and return.
//
//       In the following it is assumed that the segment is the idealized
//       segment that begins at RCV.NXT and does not exceed the window.
//       One could tailor actual segments to fit this assumption by
//       trimming off any portions that lie outside the window (including
//       SYN and FIN), and only processing further if the segment then
//       begins at RCV.NXT.  Segments with higher begining sequence
//       numbers may be held for later processing.
//
//   second check the RST bit,
//
//     SYN-RECEIVED STATE
//
//       If the RST bit is set
//
//         If this connection was initiated with a passive OPEN (i.e.,
//         came from the LISTEN state), then return this connection to
//         LISTEN state and return.  The user need not be informed.  If
//         this connection was initiated with an active OPEN (i.e., came
//         from SYN-SENT state) then the connection was refused, signal
//         the user "connection refused".  In either case, all segments
//         on the retransmission queue should be removed.  And in the
//         active OPEN case, enter the CLOSED state and delete the TCB,
//         and return.
//
//     ESTABLISHED
//     FIN-WAIT-1
//     FIN-WAIT-2
//     CLOSE-WAIT
//
//       If the RST bit is set then, any outstanding RECEIVEs and SEND
//       should receive "reset" responses.  All segment queues should be
//       flushed.  Users should also receive an unsolicited general
//       "connection reset" signal.  Enter the CLOSED state, delete the
//       TCB, and return.
//
//     CLOSING STATE
//     LAST-ACK STATE
//     TIME-WAIT
//
//       If the RST bit is set then, enter the CLOSED state, delete the
//       TCB, and return.
//   third check security and precedence
//
//     SYN-RECEIVED
//
//       If the security/compartment and precedence in the segment do not
//       exactly match the security/compartment and precedence in the TCB
//       then send a reset, and return.
//
//     ESTABLISHED STATE
//
//       If the security/compartment and precedence in the segment do not
//       exactly match the security/compartment and precedence in the TCB
//       then send a reset, any outstanding RECEIVEs and SEND should
//       receive "reset" responses.  All segment queues should be
//       flushed.  Users should also receive an unsolicited general
//       "connection reset" signal.  Enter the CLOSED state, delete the
//       TCB, and return.
//
//     Note this check is placed following the sequence check to prevent
//     a segment from an old connection between these ports with a
//     different security or precedence from causing an abort of the
//     current connection.
//
//   fourth, check the SYN bit,
//
//     SYN-RECEIVED
//     ESTABLISHED STATE
//     FIN-WAIT STATE-1
//     FIN-WAIT STATE-2
//     CLOSE-WAIT STATE
//     CLOSING STATE
//     LAST-ACK STATE
//     TIME-WAIT STATE
//
//       If the SYN is in the window it is an error, send a reset, any
//       outstanding RECEIVEs and SEND should receive "reset" responses,
//       all segment queues should be flushed, the user should also
//       receive an unsolicited general "connection reset" signal, enter
//       the CLOSED state, delete the TCB, and return.
//
//       If the SYN is not in the window this step would not be reached
//       and an ack would have been sent in the first step (sequence
//       number check).
//
//   fifth check the ACK field,
//
//     if the ACK bit is off drop the segment and return
//
//     if the ACK bit is on
//
//       SYN-RECEIVED STATE
//
//         If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
//         and continue processing.
//
//           If the segment acknowledgment is not acceptable, form a
//           reset segment,
//
//             <SEQ=SEG.ACK><CTL=RST>
//
//           and send it.
//
//       ESTABLISHED STATE
//
//         If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
//         Any segments on the retransmission queue which are thereby
//         entirely acknowledged are removed.  Users should receive
//         positive acknowledgments for buffers which have been SENT and
//         fully acknowledged (i.e., SEND buffer should be returned with
//         "ok" response).  If the ACK is a duplicate
//         (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
//         something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
//         drop the segment, and return.
//
//         If SND.UNA < SEG.ACK =< SND.NXT, the send window should be
//         updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
//         SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
//         SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.
//
//         Note that SND.WND is an offset from SND.UNA, that SND.WL1
//         records the sequence number of the last segment used to update
//         SND.WND, and that SND.WL2 records the acknowledgment number of
//         the last segment used to update SND.WND.  The check here
//         prevents using old segments to update the window.
//
//       FIN-WAIT-1 STATE
//
//         In addition to the processing for the ESTABLISHED state, if
//         our FIN is now acknowledged then enter FIN-WAIT-2 and continue
//         processing in that state.
//
//       FIN-WAIT-2 STATE
//
//         In addition to the processing for the ESTABLISHED state, if
//         the retransmission queue is empty, the user's CLOSE can be
//         acknowledged ("ok") but do not delete the TCB.
//
//       CLOSE-WAIT STATE
//
//         Do the same processing as for the ESTABLISHED state.
//
//       CLOSING STATE
//
//         In addition to the processing for the ESTABLISHED state, if
//         the ACK acknowledges our FIN then enter the TIME-WAIT state,
//         otherwise ignore the segment.
//
//       LAST-ACK STATE
//
//         The only thing that can arrive in this state is an
//         acknowledgment of our FIN.  If our FIN is now acknowledged,
//         delete the TCB, enter the CLOSED state, and return.
//
//       TIME-WAIT STATE
//
//         The only thing that can arrive in this state is a
//         retransmission of the remote FIN.  Acknowledge it, and restart
//         the 2 MSL timeout.
//
//   sixth, check the URG bit,
//
//     ESTABLISHED STATE
//     FIN-WAIT-1 STATE
//     FIN-WAIT-2 STATE
//
//       If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal
//       the user that the remote side has urgent data if the urgent
//       pointer (RCV.UP) is in advance of the data consumed.  If the
//       user has already been signaled (or is still in the "urgent
//       mode") for this continuous sequence of urgent data, do not
//       signal the user again.
//
//     CLOSE-WAIT STATE
//     CLOSING STATE
//     LAST-ACK STATE
//     TIME-WAIT
//
//       This should not occur, since a FIN has been received from the
//       remote side.  Ignore the URG.
//
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
//
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
            tcp_data_init(si, entry);
            int iss = rand();
            tcp_data->ISS = iss;
            tcp_data->SND_UNA = iss;
            tcp_data->SND_NXT = iss + 1;
            tcp_data->SND_WND = 4096;

            tcp_packet_t *packet = calloc(1, sizeof(tcp_packet_t));
            tcphdr_t *header;
            uint8_t payload = 0;
            chitcpd_tcp_packet_create(entry, &packet, &payload, 1);
            header = TCP_PACKET_HEADER(packet);
            header->seq = chitcp_htonl(tcp_data.ISS);
            header->win = chitcp_htons(tcp_data.SND_WND);
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
        return chitcpd_tcp_packet_arrival_handle(si, entry)
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
        return chitcpd_tcp_packet_arrival_handle(si, entry)
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
