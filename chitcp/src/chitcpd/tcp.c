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
    pthread_mutex_init(&tcp_data->rt_lock, NULL);

    /* Initialization of additional tcp_data_t fields,
     * and creation of retransmission thread, goes here */

    tcp_data->RCV_WND = TCP_BUFFER_SIZE;

    tcp_data->rt_queue = NULL;
    tcp_data->mt = calloc(1, sizeof(multi_timer_t));
    mt_init(tcp_data->mt, TCP_NUM_TIMERS);
    tcp_data->rto = 3 * MIN_RTO;
    tcp_data->srtt = 0;
    tcp_data->rttvar = 0;
    tcp_data->probe_packet = calloc(1, sizeof(tcp_packet_t));
    tcp_data->probe_seq = 0;
    tcp_data->ooo_packets = NULL;
}

void tcp_data_free(serverinfo_t *si, chisocketentry_t *entry)
{
    chilog(INFO, "in tcp_data_free");
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    rt_queue_elem_t *rt_elem, *tmp;

    mt_free(tcp_data->mt);

    pthread_mutex_lock(&tcp_data->rt_lock);
    DL_FOREACH_SAFE(tcp_data->rt_queue, rt_elem, tmp)
    {
        DL_DELETE(tcp_data->rt_queue, rt_elem);
        free(rt_elem->packet);
        free(rt_elem);

    }
    pthread_mutex_unlock(&tcp_data->rt_lock);

    circular_buffer_free(&tcp_data->send);
    circular_buffer_free(&tcp_data->recv);
    chitcp_packet_list_destroy(&tcp_data->pending_packets);
    pthread_mutex_destroy(&tcp_data->lock_pending_packets);
    pthread_cond_destroy(&tcp_data->cv_pending_packets);
    pthread_mutex_destroy(&tcp_data->rt_lock);

    /* Cleanup of additional tcp_data_t fields goes here */
    chilog(INFO, "Exiting tcp_data_free");

}

typedef struct rt_callback_args
{

    serverinfo_t *si;
    chisocketentry_t *entry;

} rt_callback_args_t;

/* NAME: rt_callback
 *
 * DESCRIPTION: This function generates a TIMEOUT_RTX event when the
 * retransmission timer expires
 *
 * PARAMETERS:
 *  mt        - the tcp_data multi_timer
 *  rt_timer  - the retranmission timer
 *  aux       - auxilary data
 *
 * RETURN: CHITCP_OK upon completion
 */
static void rt_callback (multi_timer_t* mt, single_timer_t* rt_timer, void* aux);
static void pt_callback(multi_timer_t* mt, single_timer_t* rt_timer, void* aux);

/* NAME: chitcpd_rtx_timeout_handle
 *
 * DESCRIPTION: This function handles a TIMEOUT_RTX event by resending
 * everything in the retransmission queue in order from oldest one that
 * was sent to the newest one. It also doubles the RTO, as specified in the
 * RFC and resets the retranmission timer for the new RTO based on the time
 * of the earliest message that was resent.
 *
 * PARAMETERS:
 *  si    - the serverinfo needed to provide to the callback args for RT timer
 *  entry - chisocket entry for this connection
 *
 * RETURN: CHITCP_OK upon completion
 */
static int chitcpd_rtx_timeout_handle(serverinfo_t *si, chisocketentry_t *entry);
static int chitcpd_pst_timeout_handle(serverinfo_t *si, chisocketentry_t *entry);

/* NAME: update_rtt
 *
 * DESCRIPTION: Updates the tcp_data struct SRTT, RTTVAR, and RTO fields
 * based on a RTT that is calculated from the difference when a packet in
 * the provided rt_elem was sent and the current time. Note that this function
 * is called by rt_queue_removed_acked_segs, and it must be called with rto_lock
 * already locked, since both update_rtt and its calling function both make
 * edits to data structures that are protected from race conditions by the rto_lock
 *
 * PARAMETERS:
 *  tcp_data  - the tcp_data struct where the SRTT, RTTVAR, and RTO variables are stored
 *  rt_elem   - the rt_elem with a packet that was just acknowledged by remote
 *
 * RETURN: CHITCP_OK upon completion
 */
static int update_rtt(tcp_data_t *tcp_data, rt_queue_elem_t *rt_elem);

/* NAME: rt_queue_removed_acked_segs
 *
 * DESCRIPTION: Whenever a incoming packet contains a valid ACK, this function
 * is called to remove all packets from the retransmission queue that were
 * acknowledged by this ACK. It also updates the connection's SND_UNA variable
 * accordingly and the RTO variable by calling update_rtt. It cancels the RT timer
 * when at least one packet in the RT queue was determined to be acknowledged and
 * resets it for the first rt_elem to not be acknowledged by the ACK, if any.
 *
 * PARAMETERS:
 *  si      - the serverinfo needed to provide to the callback args for RT timer 
 *  entry   - chisocket entry for this connection
 *  ack_seq - the next byte that the remote connection is expecting
 *
 * RETURN: CHITCP_OK upon completion
 */
static int rt_queue_removed_acked_segs(serverinfo_t *si, chisocketentry_t *entry, tcp_seq ack_seq);

/* NAME: format_and_send_packet
 *
 * DESCRIPTION: This function handles creating and sending packet with specified
 * data and flags.
 *
 * PARAMETERS:
 *  si          - server information
 *  entry       - chisocket entry for this connection
 *  payload     - data to be sent
 *  payload_len - length in bytes of data to be sent
 *  syn         - boolean to say if packet should include a syn flag
 *  fin         - boolean to say if packet should include a fin flag
 *
 * RETURN: CHITCP_OK upon completion
 */
static int format_and_send_packet(serverinfo_t *si, chisocketentry_t *entry,
                    uint8_t *payload, uint16_t payload_len, bool syn, bool fin);

/* NAME: check_and_send_from_buffer
 *
 * DESCRIPTION: This function checks if there is data to send in the send buffer
 * and if there is room in the effective window to send it.
 *
 * PARAMETERS:
 *  si    - server information
 *  entry - chisocket entry for this connection
 *
 * RETURN: CHITCP_OK upon completion
 */
static int check_and_send_from_buffer(serverinfo_t *si, chisocketentry_t *entry);

/* NAME: chitcpd_tcp_packet_arrival_handle
 *
 * DESCRIPTION: This function handles PACKET_ARRIVAL event in all states.
 *
 * PARAMETERS:
 *  si    - server information
 *  entry - chisocket entry for this connection
 *
 * RETURN: CHITCP_OK upon completion
 */
static int chitcpd_tcp_packet_arrival_handle(serverinfo_t *si, chisocketentry_t *entry);

int chitcpd_tcp_state_handle_CLOSED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    single_timer_t *rt_timer;

    if (event == APPLICATION_CONNECT)
    {

        if (entry->actpas_type == SOCKET_PASSIVE)
        {
            chitcpd_update_tcp_state(si, entry, LISTEN);
        }
        else if (entry->actpas_type == SOCKET_ACTIVE)
        {
            int iss = rand() * 1000;
            tcp_data->ISS = iss;
            tcp_data->SND_UNA = iss;
            tcp_data->SND_NXT = iss + 1;
            tcp_data->RCV_WND = TCP_BUFFER_SIZE;
            circular_buffer_set_seq_initial(&tcp_data->send, iss + 1);

            tcp_packet_t *packet = calloc(1, sizeof(tcp_packet_t));
            tcphdr_t *header;
            chitcpd_tcp_packet_create(entry, packet, NULL, 0);
            header = TCP_PACKET_HEADER(packet);
            header->seq = chitcp_htonl(tcp_data->ISS);
            header->win = chitcp_htons(tcp_data->RCV_WND);
            header->syn = 1;

            chilog(INFO, "handle CLOSED sending syn");
            /* Send packet and add to retransmission queue */
            pthread_mutex_lock(&tcp_data->rt_lock);
            rt_queue_elem_t *rt_elem = calloc(1, sizeof(rt_queue_elem_t));
            rt_elem->packet = packet;
            clock_gettime(CLOCK_REALTIME, &rt_elem->time_sent);
            chilog(INFO, "seg_seq = %u, seg_len = %u", SEG_SEQ(packet), SEG_LEN(packet));
            chitcpd_send_tcp_packet(si, entry, packet);

            /* If the retransmission queue is empty, then set timer */
            if (tcp_data->rt_queue == NULL)
            {
                rt_callback_args_t *callback_args = calloc (1, sizeof(rt_callback_args_t));
                callback_args->si = si;
                callback_args->entry = entry;
                mt_set_timer(tcp_data->mt, RT_TIMER_ID, tcp_data->rto, rt_callback, callback_args);
            }
            chilog(INFO, "APPENDING PACKET TO RT_QUEUE");
            DL_APPEND(tcp_data->rt_queue, rt_elem);
            pthread_mutex_unlock(&tcp_data->rt_lock);

            chitcpd_update_tcp_state(si, entry, SYN_SENT);
            chilog(INFO, "exiting handle CLOSED");
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
        return chitcpd_rtx_timeout_handle(si , entry);
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
        return chitcpd_rtx_timeout_handle(si , entry);
    }
    else
        chilog(WARNING, "In SYN_SENT state, received unexpected event.");

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_ESTABLISHED(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_SEND)
    {
       check_and_send_from_buffer(si, entry);
    }
    else if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        tcp_data->RCV_NXT = circular_buffer_next(&tcp_data->recv);
    }
    else if (event == APPLICATION_CLOSE)
    {
        check_and_send_from_buffer(si, entry);
        chitcpd_update_tcp_state(si, entry, FIN_WAIT_1);
        if (circular_buffer_count(&tcp_data->send) == 0)
        {
            format_and_send_packet(si, entry, NULL, 0, false, true);
            tcp_data->SND_NXT += 1;
        }
        else
        {
            tcp_data->waiting_for_empty_send_buffer = true;
        }

    }
    else if (event == TIMEOUT_RTX)
    {
        return chitcpd_rtx_timeout_handle(si , entry);
    }
    else if (event == TIMEOUT_PST)
    {
        return chitcpd_pst_timeout_handle(si , entry);
    }
    else
        chilog(WARNING, "In ESTABLISHED state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

int chitcpd_tcp_state_handle_FIN_WAIT_1(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        tcp_data->RCV_NXT = circular_buffer_next(&tcp_data->recv);
    }
    else if (event == TIMEOUT_RTX)
    {
        return chitcpd_rtx_timeout_handle(si , entry);
    }
    else if (event == TIMEOUT_PST)
    {
        return chitcpd_pst_timeout_handle(si , entry);
    }
    else
       chilog(WARNING, "In FIN_WAIT_1 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_FIN_WAIT_2(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else if (event == APPLICATION_RECEIVE)
    {
        tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
        tcp_data->RCV_NXT = circular_buffer_next(&tcp_data->recv);
    }
    else if (event == TIMEOUT_RTX)
    {
        return chitcpd_rtx_timeout_handle(si , entry);
    }
    else
        chilog(WARNING, "In FIN_WAIT_2 state, received unexpected event (%i).", event);

    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSE_WAIT(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{

    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    if (event == APPLICATION_CLOSE)
    {
        check_and_send_from_buffer(si, entry);
        format_and_send_packet(si, entry, NULL, 0, false, true);
        tcp_data->SND_NXT += 1;
        chitcpd_update_tcp_state(si, entry, LAST_ACK);

    }
    else if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        return chitcpd_rtx_timeout_handle(si , entry);
    }
    else if (event == TIMEOUT_PST)
    {
        return chitcpd_pst_timeout_handle(si , entry);
    }
    else
       chilog(WARNING, "In CLOSE_WAIT state, received unexpected event (%i).", event);


    return CHITCP_OK;
}


int chitcpd_tcp_state_handle_CLOSING(serverinfo_t *si, chisocketentry_t *entry, tcp_event_type_t event)
{
    if (event == PACKET_ARRIVAL)
    {
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        return chitcpd_rtx_timeout_handle(si , entry);
    }
    else if (event == TIMEOUT_PST)
    {
        return chitcpd_pst_timeout_handle(si , entry);
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
        return chitcpd_tcp_packet_arrival_handle(si, entry);
    }
    else if (event == TIMEOUT_RTX)
    {
        return chitcpd_rtx_timeout_handle(si , entry);
    }
    else if (event == TIMEOUT_PST)
    {
        return chitcpd_pst_timeout_handle(si , entry);
    }
    else
       chilog(WARNING, "In LAST_ACK state, received unexpected event (%i).", event);

    return CHITCP_OK;
}

/*                                                           */
/*     Any additional functions you need should go here      */
/*                                                           */

static void rt_callback (multi_timer_t* mt, single_timer_t* rt_timer, void* aux)
{
    chilog(INFO, "RETRANSMISSION");
    rt_callback_args_t *args = (rt_callback_args_t *) aux;
    chitcpd_timeout(args->si, args->entry, RETRANSMISSION);
}

static void pt_callback(multi_timer_t* mt, single_timer_t* rt_timer, void* aux)
{
    chilog(INFO, "in pt_callback");
    rt_callback_args_t *args = (rt_callback_args_t *) aux;
    chitcpd_timeout(args->si, args->entry, PERSIST);
}

static int chitcpd_rtx_timeout_handle(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    rt_queue_elem_t *rt_elem;
    pthread_mutex_lock(&tcp_data->rt_lock);
    tcp_data->rto *= 2;
    rt_elem = tcp_data->rt_queue;

    for (rt_elem = tcp_data->rt_queue; rt_elem; rt_elem = rt_elem->next)
    {
        clock_gettime(CLOCK_REALTIME, &rt_elem->time_sent);
        chitcpd_send_tcp_packet(si, entry, rt_elem->packet);
    }
    rt_elem = tcp_data->rt_queue;
    if (rt_elem != NULL)
    {
        rt_callback_args_t *callback_args = calloc(1, sizeof(rt_callback_args_t));
        callback_args->si = si;
        callback_args->entry = entry;
        mt_set_timer(tcp_data->mt, RT_TIMER_ID, tcp_data->rto, rt_callback, callback_args);
    }
    pthread_mutex_unlock(&tcp_data->rt_lock);

    return CHITCP_OK;
}

static int chitcpd_pst_timeout_handle(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    chilog(INFO, "in pst timeout handle %i", circular_buffer_count(&tcp_data->send));
    int nbytes;
    uint8_t probe_byte;
    tcphdr_t *send_header;
    chilog(INFO, "probe seq: %u, send una: %u", tcp_data->probe_seq, tcp_data->SND_UNA);
    if (tcp_data->SND_UNA <= tcp_data->probe_seq)
    {
        /* Last probe segment was never acknowledged, so send it again */
        chilog(INFO, "ARTUR - RESENDING PROBE");
        chitcpd_send_tcp_packet(si, entry, tcp_data->probe_packet);
    }
    else if (circular_buffer_count(&tcp_data->send) > 0)
    {
        chilog(INFO, "ARTUR - SENDING NEW PROBE");
        /* There is data to send, send a probe segment */
        nbytes = circular_buffer_read(&tcp_data->send, &probe_byte, 1, true);
        if (nbytes == 1)
        {
            tcp_data->probe_seq = tcp_data->SND_NXT;
            chitcpd_tcp_packet_create(entry, tcp_data->probe_packet, &probe_byte, nbytes);
            send_header = TCP_PACKET_HEADER(tcp_data->probe_packet);
            send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
            send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
            send_header->win = chitcp_htons(tcp_data->RCV_WND);
            send_header->ack = 1;
            tcp_data->SND_NXT += nbytes;
            chitcpd_send_tcp_packet(si, entry, tcp_data->probe_packet);
        }
        else
        {
            /* This should not happen, there should be an error */
        }
    }
    /* Always reset the persist timer */
    rt_callback_args_t *callback_args = calloc(1, sizeof(rt_callback_args_t));
    callback_args->si = si;
    callback_args->entry = entry;
    mt_set_timer(tcp_data->mt, PERSIST_TIMER_ID, tcp_data->rto, pt_callback, callback_args);
    return CHITCP_OK;
}

static int update_rtt(tcp_data_t *tcp_data, rt_queue_elem_t *rt_elem)
{
    struct timespec now, diff;
    clock_gettime(CLOCK_REALTIME, &now);
    timespec_subtract(&diff, &now, &rt_elem->time_sent);
    uint64_t rtt = (diff.tv_sec * SECOND) + diff.tv_nsec;
    if (tcp_data->srtt == 0 && tcp_data->rttvar == 0)  // First RTT measurement
    {
        tcp_data->srtt = rtt;
        tcp_data->rttvar = rtt / 2;
        tcp_data->rto = tcp_data->srtt + MAX(CLOCK_GRANULARITY, (4 * tcp_data->rttvar));
    }
    else
    {
        if (tcp_data->srtt > rtt)
        {
            tcp_data->rttvar = (1 - BETA) * (tcp_data->rttvar + (BETA * (tcp_data->srtt - rtt)));
        }
        else
        {
            tcp_data->rttvar = (1 - BETA) * (tcp_data->rttvar + (BETA * (rtt - tcp_data->srtt)));
        }

        tcp_data->srtt = (1 - ALPHA) * (tcp_data->srtt + (ALPHA * rtt));
        tcp_data->rto = tcp_data->srtt + MAX(CLOCK_GRANULARITY, 4 * (tcp_data->rttvar));
        if (tcp_data->rto < MIN_RTO)
        {
            tcp_data->rto = MIN_RTO;
        }
    }
    return CHITCP_OK;
}

static int rt_queue_removed_acked_segs(serverinfo_t *si, chisocketentry_t *entry, tcp_seq ack_seq)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *p;
    rt_queue_elem_t *rt_elem;
    pthread_mutex_lock(&tcp_data->rt_lock);

    rt_elem = tcp_data->rt_queue;
    if (rt_elem != NULL)
    {
        p = rt_elem->packet;
        if (SEG_SEQ(p) + SEG_LEN(p) <= ack_seq)
        {
            update_rtt(tcp_data, rt_elem);
            mt_cancel_timer(tcp_data->mt, RT_TIMER_ID);
            DL_DELETE(tcp_data->rt_queue, rt_elem);
            tcp_data->SND_UNA = SEG_SEQ(p) + SEG_LEN(p);
            for (rt_elem = rt_elem->next; rt_elem; rt_elem = rt_elem->next)
            {
                p = rt_elem->packet;
                if (SEG_SEQ(p) + SEG_LEN(p) > ack_seq)
                {
                    break;
                }
                else
                {
                    DL_DELETE(tcp_data->rt_queue, rt_elem);
                    tcp_data->SND_UNA = SEG_SEQ(p) + SEG_LEN(p);
                }
            }
            if (rt_elem != NULL)
            {
                rt_callback_args_t *callback_args = calloc(1, sizeof(rt_callback_args_t));
                callback_args->si = si;
                callback_args->entry = entry;

                mt_set_timer(tcp_data->mt, RT_TIMER_ID, tcp_data->rto, rt_callback, callback_args);
            }
        }
    }

    pthread_mutex_unlock(&tcp_data->rt_lock);

    return CHITCP_OK;
}

static int format_and_send_packet(serverinfo_t *si, chisocketentry_t *entry,
                     uint8_t *payload, uint16_t payload_len, bool syn, bool fin)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *send_packet = calloc(1, sizeof(tcp_packet_t));
    tcphdr_t *send_header;
    single_timer_t *rt_timer;
    int ret;

    chitcpd_tcp_packet_create(entry, send_packet, payload, payload_len);
    send_header = TCP_PACKET_HEADER(send_packet);
    send_header->seq = chitcp_htonl(tcp_data->SND_NXT);
    send_header->ack_seq = chitcp_htonl(tcp_data->RCV_NXT);
    send_header->win = chitcp_htons(tcp_data->RCV_WND);
    send_header->ack = 1;
    if (syn)
    {
        send_header->syn = 1;
    }
    if (fin)
    {
        send_header->fin = 1;
    }
    /* Send packet and add to retransmission queue */
    pthread_mutex_lock(&tcp_data->rt_lock);
    rt_queue_elem_t *rt_elem = calloc(1, sizeof(rt_queue_elem_t));
    rt_elem->packet = send_packet;
    clock_gettime(CLOCK_REALTIME, &rt_elem->time_sent);
    chitcpd_send_tcp_packet(si, entry, send_packet);

    /* If the retransmission queue is empty, then set timer */
    if (SEG_LEN(send_packet) > 0)
    {
        if (tcp_data->rt_queue == NULL)
        {
            rt_callback_args_t *callback_args = calloc (1, sizeof(rt_callback_args_t));
            callback_args->si = si;
            callback_args->entry = entry;
            mt_set_timer(tcp_data->mt, RT_TIMER_ID, tcp_data->rto, rt_callback, callback_args);
        }
        DL_APPEND(tcp_data->rt_queue, rt_elem);
    }

    pthread_mutex_unlock(&tcp_data->rt_lock);

    return CHITCP_OK;
}

static int check_and_send_from_buffer(serverinfo_t *si, chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    uint8_t data_to_send[TCP_MSS];
    uint32_t len;
    int nbytes;
    int effective_window = tcp_data->SND_WND - (tcp_data->SND_NXT - tcp_data->SND_UNA);
    /* check that there are items to read and that effective window > 0 */
    while ((circular_buffer_count(&tcp_data->send) > 0) && (effective_window > 0))
    {
        len = MIN(effective_window, TCP_MSS);
        nbytes = circular_buffer_read(&tcp_data->send, data_to_send, len, true);
        format_and_send_packet(si, entry, data_to_send, nbytes, false, false);
        tcp_data->SND_NXT += nbytes;
        effective_window = tcp_data->SND_WND - (tcp_data->SND_NXT - tcp_data->SND_UNA);
    }

    return CHITCP_OK;
}

static int seq_cmp(tcp_packet_list_t *packet_list_elem_a, tcp_packet_list_t *packet_list_elem_b)
{
    return SEG_SEQ(packet_list_elem_a->packet) - SEG_SEQ(packet_list_elem_b->packet);
}

static void add_out_of_order_packet(tcp_data_t *tcp_data, tcp_packet_t *packet)
{
    chilog(INFO, "ARTUR - IN ADD OUT OF ORDER");
    tcp_packet_list_t *ooo_packets = tcp_data->ooo_packets;
    tcphdr_t *header = TCP_PACKET_HEADER(packet);
    tcp_packet_list_t *ooo_packet_elem = calloc(1, sizeof(tcp_packet_list_t));
    tcp_packet_list_t *found = NULL;
    ooo_packet_elem->packet = packet;
    ooo_packet_elem->prev = NULL;
    ooo_packet_elem->next = NULL;
    DL_SEARCH(tcp_data->ooo_packets, found, ooo_packet_elem, seq_cmp);
    if (found)
    {
        chilog(INFO, "WE SHOULD GET HERE SOMETIMES");
        free(ooo_packet_elem);
        return;
    }
    DL_INSERT_INORDER(tcp_data->ooo_packets, ooo_packet_elem, seq_cmp);
    // if (ooo_packets == NULL)
    // {
    //     /* out of order list was empty */
    //     tcp_data->ooo_packets = ooo_packet_elem;
    //     return;
    // }
    // if (SEG_SEQ(packet) < SEG_SEQ(ooo_packets->packet))
    // {
    //     chilog(INFO, "WE SHOULD GET HERE AT SOME POINT");
    //     /* packet has sequence less than head of list, so make it the head */
    //     tcp_data->ooo_packets = ooo_packet_elem;
    //     ooo_packets->prev = ooo_packet_elem;
    //     ooo_packet_elem->next = ooo_packets;
    //     return;
    // }
    // while (SEG_SEQ(packet) >= SEG_SEQ(ooo_packets->packet))
    // {
    //     if (SEG_SEQ(packet) == SEG_SEQ(ooo_packets->packet))
    //     {
    //         /* packet is already in out of order */
    //         free(ooo_packet_elem);
    //         return;
    //     }
    //     if (ooo_packets->next == NULL)
    //     {
    //         ooo_packets->next = ooo_packet_elem;
    //         ooo_packet_elem->prev = ooo_packets;
    //         return;
    //     }
    //     ooo_packets = ooo_packets->next;
    // }
    // ooo_packet_elem->next = ooo_packets;
    // ooo_packet_elem->prev = ooo_packets->prev;
    // ooo_packets->prev->next = ooo_packet_elem;
    // ooo_packets->prev = ooo_packet_elem;
}

static void check_head_ooo_packets(tcp_data_t *tcp_data)
{
    chilog(INFO, "ARTUR - IN CHECKING OOO PACKETS");
    tcp_packet_list_t *ooo_packets = tcp_data->ooo_packets;
    if (ooo_packets == NULL)
    {
        return;
    }
    chilog(INFO, "packet seq: %u", SEG_SEQ(tcp_data->ooo_packets->packet));
    chilog(INFO, "rcv_nxt: %u", tcp_data->RCV_NXT);
    if (tcp_data->RCV_NXT == SEG_SEQ(tcp_data->ooo_packets->packet))
    {
        tcp_packet_t *packet = tcp_data->ooo_packets->packet;
        // tcp_data->ooo_packets = tcp_data->ooo_packets->next;
        chitcp_packet_list_pop_head(&tcp_data->ooo_packets);
        free(ooo_packets);
        chitcp_packet_list_append(&tcp_data->pending_packets, packet);
    }
}

static int chitcpd_tcp_packet_arrival_handle(serverinfo_t *si,
                                                        chisocketentry_t *entry)
{
    tcp_data_t *tcp_data = &entry->socket_state.active.tcp_data;
    tcp_packet_t *packet = NULL;
    tcphdr_t *header = NULL;
    pthread_mutex_lock(&tcp_data->lock_pending_packets);
    if (tcp_data->pending_packets)
    {
      packet = tcp_data->pending_packets->packet;
      chitcp_packet_list_pop_head(&tcp_data->pending_packets);
      pthread_mutex_unlock(&tcp_data->lock_pending_packets);
    }
    else
    {
        pthread_mutex_unlock(&tcp_data->lock_pending_packets);
        return CHITCP_OK;
    }
    header = TCP_PACKET_HEADER(packet);
    chilog(INFO, "In packet arrival handler: received packet SEQ is %u, LEN is %u, WND is %u", SEG_SEQ(packet), SEG_LEN(packet), SEG_WND(packet));
    if (SEG_WND(packet) == 0)
    {
        rt_callback_args_t *callback_args = calloc(1, sizeof(rt_callback_args_t));
        callback_args->si = si;
        callback_args->entry = entry;
        mt_set_timer(tcp_data->mt, PERSIST_TIMER_ID, tcp_data->rto, pt_callback, callback_args);
    }
    else if (SEG_WND(packet) > 0)
    {
        mt_cancel_timer(tcp_data->mt, PERSIST_TIMER_ID);
    }
    if (entry->tcp_state == CLOSED)
    {
        /* ignore packets while in CLOSED */
        return CHITCP_OK;
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
            int iss = rand() * 1000;
            tcp_data->ISS = iss;
            tcp_data->SND_NXT = iss;
            tcp_data->SND_WND = SEG_WND(packet);
            circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
            circular_buffer_set_seq_initial(&tcp_data->send, iss + 1);
            format_and_send_packet(si, entry, NULL, 0, true, false);
            tcp_data->SND_UNA = iss;
            tcp_data->SND_NXT = iss + 1;
            chitcpd_update_tcp_state(si, entry, SYN_RCVD);
        }
        else
        {
            return CHITCP_OK;
        }
    }
    else if (entry->tcp_state == SYN_SENT)
    {
        if (header->ack)
        {
            if (SEG_ACK(packet) <= tcp_data->ISS ||
                                            SEG_ACK(packet) > tcp_data->SND_NXT)
            {
                return CHITCP_OK;
            }
        }
        if (header->syn)
        {
            tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
            tcp_data->IRS = SEG_SEQ(packet);
            tcp_data->SND_WND = SEG_WND(packet);
//            tcp_data->SND_UNA = SEG_ACK(packet);
            circular_buffer_set_seq_initial(&tcp_data->recv, tcp_data->IRS + 1);
            rt_queue_removed_acked_segs(si, entry, SEG_ACK(packet));

            if (tcp_data->SND_UNA > tcp_data->ISS)
            {
                format_and_send_packet(si, entry, NULL, 0, false, false);
                chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                return CHITCP_OK;
            }
            else
            {
                format_and_send_packet(si, entry, NULL, 0, true, false);
                tcp_data->SND_NXT += 1;
                chitcpd_update_tcp_state(si, entry, SYN_RCVD);
                return CHITCP_OK;
            }
        }
        else
        {
            return CHITCP_OK;
        }
    }
    else  // All other states
    {
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
                acceptable = (tcp_data->RCV_NXT <= SEG_SEQ(packet) &&
                              SEG_SEQ(packet) < recv_end) || (tcp_data->RCV_NXT
                                              <= seq_end && seq_end < recv_end);
            }
        }
        if ((!acceptable) || (tcp_data->RCV_NXT != SEG_SEQ(packet)))
        {
            format_and_send_packet(si, entry, NULL, 0, false, false);
            if (tcp_data->RCV_NXT < SEG_SEQ(packet))
            {
                /* Add packet to out_of_order list */
                add_out_of_order_packet(tcp_data, packet);
            }
            return CHITCP_OK;
        }

        if (header->syn)
        {
            /* Should free TCB and return. It must be in the window,
             * because we just checked for acceptability above */
            memset(tcp_data, 0, sizeof (tcp_data));
            /* Flush all segment queues here */
            chitcpd_update_tcp_state(si, entry, CLOSED);
            return CHITCP_OK;
        }

        if (!header->ack)
        {
            return CHITCP_OK;
        }
        else  // Checking ACK field
        {
            if (entry->tcp_state == SYN_RCVD)
            {
                if (tcp_data->SND_UNA <= SEG_ACK(packet) && SEG_ACK(packet) <=
                                                              tcp_data->SND_NXT)
                {
                    tcp_data->SND_WND = SEG_WND(packet);
                    rt_queue_removed_acked_segs(si, entry, SEG_ACK(packet));
                    check_and_send_from_buffer(si, entry);
                    chitcpd_update_tcp_state(si, entry, ESTABLISHED);
                }
                else
                {
                    return CHITCP_OK;
                }
            }

            if (entry->tcp_state == LAST_ACK)
            {
                /* The only thing that can arrive here is ACK of our FIN.
                 * Check that our FIN is acknowledged and if so, close
                 * connection */
                if (tcp_data->SND_UNA < SEG_ACK(packet))
                {
                    rt_queue_removed_acked_segs(si, entry, SEG_ACK(packet));
                    memset(tcp_data, 0, sizeof (tcp_data));
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                    return CHITCP_OK;
                }
            }
            else if (entry->tcp_state == TIME_WAIT)
            {
                /* The only thing that can arrive here is a retransmission of
                 * connection's FIN. Acknowledge it. */
                rt_queue_removed_acked_segs(si, entry, SEG_ACK(packet));
                format_and_send_packet(si, entry, NULL, 0, false, false);
            }
            else
            {
                /* All other possible processing of ACK field at minimum
                 * goes through ESTABLISHED processing: */
                if (tcp_data->SND_UNA < SEG_ACK(packet) &&
                      SEG_ACK(packet) <= tcp_data->SND_NXT)
                {
                  /* Need to remove segments in retransmission queue that
                     are acknowledged as a result of this: */
                    tcp_data->SND_WND = SEG_WND(packet);
                    rt_queue_removed_acked_segs(si, entry, SEG_ACK(packet));
                    check_and_send_from_buffer(si, entry);
                }
                else if (SEG_ACK(packet) < tcp_data->SND_UNA)
                {
                    /* Duplicate, can ignore */
                    chilog(INFO, "SEG_ACK < SND_UNA: duplicate that we can ignore");
                }
                else if (SEG_ACK(packet) > tcp_data->SND_NXT)
                {
                    /* Remote is ACKing something not yet sent; so send an ACK
                     * and return */
                    chilog(INFO, "send packet 8");
                    format_and_send_packet(si, entry, NULL, 0, false, false);
                    return CHITCP_OK;
                }

                /* Additional processing in addition to base required by
                 * all above */
                if (entry->tcp_state == FIN_WAIT_1)
                {

                    if (tcp_data->waiting_for_empty_send_buffer &&
                          circular_buffer_count(&tcp_data->send) == 0)
                    {
                        format_and_send_packet(si, entry, NULL, 0, false, true);
                        tcp_data->SND_NXT += 1;
                        tcp_data->waiting_for_empty_send_buffer = false;
                    }
                    /* If our FIN is now acknowledged, enter FIN_WAIT_2 and
                     * continue processing */
                    if (tcp_data->SND_UNA == tcp_data->SND_NXT)
                    {
                        chitcpd_update_tcp_state(si, entry, FIN_WAIT_2);
                    }
                }

                if (entry->tcp_state == CLOSING)
                {
                    /* If the ACK acknowledges our FIN, then enter the TIME_WAIT
                     * state, otherwise ignore the segment.
                     * The ACK must have acknowledged our fin because we already
                     * checked that ACK > SND_UNA above. */
                    if (tcp_data->SND_UNA == tcp_data->SND_NXT)
                    {
                        chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                        chitcpd_update_tcp_state(si, entry, CLOSED);
                    }

                }

            }
        }
        /* Processing the segment text: */
        if (TCP_PAYLOAD_LEN(packet) > 0)
        {
            int nbytes = 0;
            switch (entry->tcp_state)
            {
                case ESTABLISHED:
                case FIN_WAIT_1:
                case FIN_WAIT_2:
                    /* Add segment text to user RECEIVE buffer */
                    nbytes = circular_buffer_write(&tcp_data->recv,
                      TCP_PAYLOAD_START(packet), TCP_PAYLOAD_LEN(packet), true);
                    /* This is where we will check the out-of-order list */
                    tcp_data->RCV_NXT = circular_buffer_next(&tcp_data->recv);
                    tcp_data->RCV_WND = circular_buffer_available(&tcp_data->recv);
                    check_head_ooo_packets(tcp_data);
                    format_and_send_packet(si, entry, NULL, 0, false, false);
                    break;
                case CLOSE_WAIT:
                case CLOSING:
                case LAST_ACK:
                case TIME_WAIT:
                    /* Should not occur, since a FIN has been received from
                     * the remote side */
                    break;
                default:
                    break;
            }
        }
        /* Check FIN bit: */
        if (header->fin)
        {
            if (entry->tcp_state == CLOSED || entry->tcp_state == LISTEN ||
                entry->tcp_state == SYN_SENT)
            {
                return CHITCP_OK;
            }
            /* Signal the user "connection closing"
             * Return any pending RECEIVES with the same message */
            tcp_data->RCV_NXT = SEG_SEQ(packet) + 1;
            format_and_send_packet(si, entry, NULL, 0, false, false);

            switch (entry->tcp_state)
            {
                case SYN_RCVD:
                case ESTABLISHED:
                    chitcpd_update_tcp_state(si, entry, CLOSE_WAIT);
                    break;
                case FIN_WAIT_1:
                    /* If our FIN has been ACKed (perhaps in this segment), then
                       enter TIME_WAIT, otherwise enter the CLOSING state */
                    format_and_send_packet(si, entry, NULL, 0, false, false);
                    chitcpd_update_tcp_state(si, entry, CLOSING);
                    break;
                case FIN_WAIT_2:
                    chitcpd_update_tcp_state(si, entry, TIME_WAIT);
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                    break;
                case TIME_WAIT:
                    /* Restart the 2 MSL time-wait timeout */
                    chitcpd_update_tcp_state(si, entry, CLOSED);
                    break;
                default: // Do Nothing
                    break;
            }
        }
    }
}
