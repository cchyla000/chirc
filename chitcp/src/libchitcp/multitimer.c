/*
 *  chiTCP - A simple, testable TCP stack
 *
 *  An API for managing multiple timers
 */

/*
 *  Copyright (c) 2013-2019, The University of Chicago
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "chitcp/multitimer.h"
#include "chitcp/log.h"
#include "chitcp/utlist.h"

#define NANO_PER_SEC 1000000000L

/* single_timer_compare - Compares two active timers by their timeouts.
 *
 * Used to maintain sorted timer_list in increasing order of timeout times
 *
 * x, y: active timers to compare
 *
 * Returns: 1 if x->timeout < y->timeout,
 *          0 if x->timeout = y->timeout,
 *          1 if x->timeout > y->timeout
 */
static int single_timer_compare(single_timer_t *x, single_timer_t *y);

static bool timer_expired(single_timer_t *timer);

static void *timer_thread_func(void *args);



/* See multitimer.h */
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y)
{
    struct timespec tmp;
    tmp.tv_sec = y->tv_sec;
    tmp.tv_nsec = y->tv_nsec;

    /* Perform the carry for the later subtraction by updating tmp. */
    if (x->tv_nsec < tmp.tv_nsec) {
        uint64_t sec = (tmp.tv_nsec - x->tv_nsec) / SECOND + 1;
        tmp.tv_nsec -= SECOND * sec;
        tmp.tv_sec += sec;
    }
    if (x->tv_nsec - tmp.tv_nsec > SECOND) {
        uint64_t sec = (x->tv_nsec - tmp.tv_nsec) / SECOND;
        tmp.tv_nsec += SECOND * sec;
        tmp.tv_sec -= sec;
    }

    /* Compute the time remaining to wait.
       tv_nsec is certainly positive. */
    result->tv_sec = x->tv_sec - tmp.tv_sec;
    result->tv_nsec = x->tv_nsec - tmp.tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < tmp.tv_sec;
}


/* See multitimer.h */
int mt_init(multi_timer_t *mt, uint16_t num_timers)
{
    int i;
    single_timer_t *timer;
    pthread_t multi_timer_thread;
    mt->num_timers = num_timers;
    mt->timer_list = NULL;  // Must ensure it is zeroed for utlish to work
    mt->timer_array = calloc(num_timers, sizeof(single_timer_t));
    if (!mt->timer_array)
    {
        return CHITCP_ENOMEM;
    }
    else if (pthread_mutex_init(&mt->mutex, NULL) != 0)
    {
        free(mt->timer_array);
        return CHITCP_EINIT;
    }
    else if (pthread_cond_init(&mt->cond, NULL) != 0)
    {
        free(mt->timer_array);
        free(&mt->mutex);
        return CHITCP_EINIT;
    }

    for (i=0; i < num_timers; i++)
    {
        timer = &mt->timer_array[i];
        timer->id = i;
    }

    /* Create multitimer thread */
    if (pthread_create(&multi_timer_thread, NULL, timer_thread_func, (void *) mt) != 0)
    {
        free(mt->timer_array);
        free(&mt->mutex);
        free(&mt->cond);
        return CHITCP_ETHREAD;
    }
    else
    {
        mt->multi_timer_thread = multi_timer_thread;
    }

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_free(multi_timer_t *mt)
{
    pthread_cancel(mt->multi_timer_thread);

    free(mt->timer_array);
    free(mt->timer_list);
    pthread_mutex_destroy(&mt->mutex);
    pthread_cond_destroy(&mt->cond);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_get_timer_by_id(multi_timer_t *mt, uint16_t id, single_timer_t **timer)
{

    if (id >= mt->num_timers)
    {
        return CHITCP_EINVAL;
    }
    else
    {
        *timer = &mt->timer_array[id];
    }


    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer(multi_timer_t *mt, uint16_t id, uint64_t timeout, mt_callback_func callback, void* callback_args)
{
    single_timer_t *timer;
    long tmp_nsec;

    pthread_mutex_lock(&mt->mutex);
    if (id >= mt->num_timers)
    {
        pthread_mutex_unlock(&mt->mutex);
        return CHITCP_EINVAL;
    }

    timer = &mt->timer_array[id];

    if (timer->active)
    {
        pthread_mutex_unlock(&mt->mutex);
        return CHITCP_EINVAL;
    }
    else
    {
        timer->active = true;
        timer->callback = callback;
        timer->callback_args = callback_args;
        clock_gettime(CLOCK_REALTIME, &timer->timeout);
        tmp_nsec = timeout + timer->timeout.tv_nsec;
        timer->timeout.tv_nsec = tmp_nsec % NANO_PER_SEC;
        timer->timeout.tv_sec += (tmp_nsec / NANO_PER_SEC);
        LL_INSERT_INORDER(mt->timer_list, timer, single_timer_compare);

        /* Signal multitimer to reset its timedwait, which
         * could have changed as a result of this newly set timer */
        pthread_mutex_unlock(&mt->mutex);
        pthread_cond_signal(&mt->cond);

    }

    return CHITCP_OK;

}


/* See multitimer.h */
int mt_cancel_timer(multi_timer_t *mt, uint16_t id)
{
    pthread_mutex_lock(&mt->mutex);
    if (id >= mt->num_timers)
    {
        pthread_mutex_unlock(&mt->mutex);
        return CHITCP_EINVAL;
    }

    single_timer_t *timer = &mt->timer_array[id];

    if (!timer->active)
    {
        pthread_mutex_unlock(&mt->mutex);
        return CHITCP_EINVAL;
    }
    else
    {
        LL_DELETE(mt->timer_list, timer);
        timer->active = false;
        pthread_mutex_unlock(&mt->mutex);
    }

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_set_timer_name(multi_timer_t *mt, uint16_t id, const char *name)
{
    if (id >= mt->num_timers)
    {
        return CHITCP_EINVAL;
    }
    else
    {
        strncpy(mt->timer_array[id].name, name, MAX_TIMER_NAME_LEN);
    }

    return CHITCP_OK;
}


/* mt_chilog_single_timer - Prints a single timer using chilog
 *
 * level: chilog log level
 *
 * timer: Timer
 *
 * Returns: Always returns CHITCP_OK
 */
int mt_chilog_single_timer(loglevel_t level, single_timer_t *timer)
{
    struct timespec now, diff;
    clock_gettime(CLOCK_REALTIME, &now);

    if(timer->active)
    {
        /* Compute the appropriate value for "diff" here; it should contain
         * the time remaining until the timer times out.
         * Note: The timespec_subtract function can come in handy here*/
        diff.tv_sec = 0;
        diff.tv_nsec = 0;
        chilog(level, "%i %s %lis %lins", timer->id, timer->name, diff.tv_sec, diff.tv_nsec);
    }
    else
        chilog(level, "%i %s", timer->id, timer->name);

    return CHITCP_OK;
}


/* See multitimer.h */
int mt_chilog(loglevel_t level, multi_timer_t *mt, bool active_only)
{
    /* Your code here */

    return CHITCP_OK;
}

static int single_timer_compare(single_timer_t *x, single_timer_t *y)
{
    int i;
    struct timespec result, time_x, time_y;
    time_x = x->timeout;
    time_y = y->timeout;
    i = timespec_subtract(&result, &time_x, &time_y);

    if (i)
    {
        /* Result is negative, so X is less than Y */
        return -1;
    }
    else if (result.tv_sec == 0 && result.tv_nsec == 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

static bool timer_expired(single_timer_t *timer)
{
    int i;
    struct timespec realtime, result;
    clock_gettime(CLOCK_REALTIME, &realtime);

    i = timespec_subtract(&result, &timer->timeout, &realtime);

    // timeout minus realtime is negative or 0, so timer is expired
    if (i || (result.tv_sec == 0 && result.tv_nsec == 0))
    {
        return true;
    }
    else return false;
}

static void *timer_thread_func(void *args)
{
    multi_timer_t *mt;
    mt = (multi_timer_t *) args;

    single_timer_t *tmp;
    struct timespec const_timespec;

    /* Handle all expired timers in linked list in order. Once done, if
     * there is a remaining active timer in linked list, do timedwait on
     * its timeout time. Else, do regular wait */

    pthread_mutex_lock(&mt->mutex);
    while (1)
    {
        for (tmp = mt->timer_list; tmp; tmp = tmp->next)
        {
             if (timer_expired(tmp))
             {
                  LL_DELETE(mt->timer_list, tmp);
                  tmp->active = false;
                  tmp->num_timeouts += 1;
                  tmp->callback(mt, tmp, tmp->callback_args);
             }
             else
             {
                 break;
             }
        }

        if (tmp == NULL)  // We have processed all the timers; wait
        {
            pthread_cond_wait(&mt->cond, &mt->mutex);
        }
        else  // Do timedwait on first timer that is unexpired
        {
            const_timespec = tmp->timeout; // Guaranteed to be constant for this specific timedwait
            pthread_cond_timedwait(&mt->cond, &mt->mutex,
              (const struct timespec *) &const_timespec);
        }

    }
    pthread_mutex_unlock(&mt->mutex);
    return NULL;
}
