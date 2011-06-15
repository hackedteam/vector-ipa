/*
    MODULE -- statistics

    Copyright (C) Alberto Ornaghi

    $Id: statistics.c 790 2009-08-03 14:34:04Z alor $
*/

#include <main.h>
#include <threads.h>

static long long heartbeat;
pthread_mutex_t hbeat_mux = PTHREAD_MUTEX_INITIALIZER;
#define HEARTBEAT_LOCK do { pthread_mutex_lock(&hbeat_mux); } while (0)
#define HEARTBEAT_UNLOCK do { pthread_mutex_unlock(&hbeat_mux); } while (0)

long long stat_get_heartbeat(void);
void stat_heartbeat(void);

// get current heartbeat
long long stat_get_heartbeat(void)
{
	long long current;

	HEARTBEAT_LOCK;
	current = heartbeat;
	HEARTBEAT_UNLOCK;

	return current;
}

// do heartbeat
// to be placed in most recurrent code blocks
void stat_heartbeat(void)
{
	HEARTBEAT_LOCK;
	heartbeat++;
	HEARTBEAT_UNLOCK;
}

struct stat_t {
	long long transferred;
	long long received;
	long long sent;
	long long throughput;
	time_t start_time;
	u_int32 packetrate;
};

static struct stat_t statistics;

void stat_init(void);
void stat_update_sent(u_int32 sent);
void stat_update_received(u_int32 received);
void stat_get(u_int32 *transferred, u_int32 *throughput, u_int32 *packetrate);
void stat_log_statistics(void);
long long stat_compute_avg_throughput(void);

/******** STATISTICS *********/

void stat_init(void)
{
	statistics.transferred = 0;
	statistics.received = 0;
	statistics.sent = 0;
	statistics.throughput = 0;
	statistics.packetrate = 0;

	statistics.start_time = time(NULL);
}

void stat_log_statistics(void)
{
	u_int32 xferred;
	u_int32 tput;

	stat_get(&xferred, &tput, NULL);

	DEBUG_MSG(D_INFO, "%s statistics [transferred %d][throughtput %d]", __func__, xferred, tput);
}

void stat_get(u_int32 *transferred, u_int32 *throughput, u_int32 *packetrate)
{

	stat_compute_avg_throughput();

	if (transferred)
		*transferred = statistics.transferred;

	if (throughput)
		*throughput = statistics.throughput;
	
	if (packetrate)
		*packetrate = statistics.packetrate;
}

void stat_update_sent(u_int32 sent)
{
	statistics.sent += sent;
	statistics.transferred += sent;
}

void stat_update_received(u_int32 received)
{
	statistics.received += received;
	statistics.transferred += received;
}

long long stat_compute_avg_throughput(void)
{
	time_t now = time(NULL);	

	// tput in bytes per second
	statistics.throughput = statistics.transferred / (u_int32)(now - statistics.start_time);

	return statistics.throughput;
}

/* EOF */

// vim:ts=3:expandtab
