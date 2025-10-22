// SPDX-License-Identifier: GPL-2.0
/*
 * MPTCP "portsched" — port-based scheduler with optional NIC pinning.
 *
 *  - Port 5000 -> REDUNDANT: schedule all subflows (or only those on a pinned NIC)
 *  - Port 6060 -> LRTT-like: pick lowest-RTT subflow (optionally pinned)
 *
 * You can change the ports via the defines below.
 *
 * Optional NIC pinning (module params):
 *   force_if_redundant=<ifname>
 *   force_if_lrtt=<ifname>
 *
 * Notes:
 * - We match on either src or dst port so both client and server sides work.
 * - If pinning is requested but no subflows are bound to that device, we log
 *   (rate-limited) and fall back to "best overall" to keep traffic flowing.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>          /* dev_get_by_name_rcu, netif_running */
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/mptcp.h>
#include "protocol.h"                 /* mptcp_sock, mptcp_for_each_subflow, helpers */

#define PORT_REDUNDANT 5000
#define PORT_LRTT      6060

/* ---- Module parameters: optional NIC pinning per mode ---- */
static char *force_if_redundant = "";
module_param(force_if_redundant, charp, 0644);
MODULE_PARM_DESC(force_if_redundant, "Interface to use in REDUNDANT mode (e.g. ens33)");

static char *force_if_lrtt = "";
module_param(force_if_lrtt, charp, 0644);
MODULE_PARM_DESC(force_if_lrtt, "Interface to use in LRTT mode (e.g. ens34)");

/* ---- Helpers ---- */
static inline u16 dport(const struct sock *sk)
{
	return ntohs(inet_sk(sk)->inet_dport);
}

static inline u16 sport(const struct sock *sk)
{
	return ntohs(inet_sk(sk)->inet_sport);
}

/* Match either endpoint so this works for client and server sides */
static inline bool port_matches(const struct mptcp_sock *msk, u16 p)
{
	const struct sock *sk = (const struct sock *)msk;
	return dport(sk) == p || sport(sk) == p;
}

static inline bool is_redundant_mode(const struct mptcp_sock *msk)
{
	return port_matches(msk, PORT_REDUNDANT);
}

static inline bool is_lrtt_mode(const struct mptcp_sock *msk)
{
	return port_matches(msk, PORT_LRTT);
}

/* If a specific NIC name is configured, translate to ifindex (0 = not pinned) */
static int want_ifindex(const struct mptcp_sock *msk, bool redundant_mode)
{
	const char *ifname = redundant_mode ? force_if_redundant : force_if_lrtt;
	struct net *netns = sock_net((struct sock *)msk);
	int idx = 0;

	if (!ifname || !*ifname)
		return 0;

	rcu_read_lock();
	{
		struct net_device *dev = dev_get_by_name_rcu(netns, ifname);
		if (dev && netif_running(dev) && netif_carrier_ok(dev))
			idx = dev->ifindex;
	}
	rcu_read_unlock();
	return idx; /* 0 => not found/not up */
}

/* ---- Core scheduling paths ---- */

/* REDUNDANT: schedule every subflow (optionally only those on ifindex) */
static int schedule_redundant(struct mptcp_sock *msk, int ifindex)
{
	bool any = false, matched = false;
	struct mptcp_subflow_context *subflow;

	mptcp_for_each_subflow(msk, subflow) {
		struct sock *ssk;
		if (!subflow)
			continue;
		any = true;

		/* Underlying TCP socket of the subflow */
		ssk = mptcp_subflow_tcp_sock(subflow);

		/* If pinned, only schedule subflows bound to that device */
		if (ifindex && ssk->sk_bound_dev_if != ifindex)
			continue;

		mptcp_subflow_set_scheduled(subflow, true);
		matched = true;
	}

	if (ifindex && any && !matched) {
		pr_info_ratelimited("portsched: pinned ifindex=%d has no subflows; falling back to all.\n",
				    ifindex);
		/* Fallback: schedule all */
		mptcp_for_each_subflow(msk, subflow) {
			if (subflow)
				mptcp_subflow_set_scheduled(subflow, true);
		}
	}
	return 0;
}

/* LRTT: select lowest-RTT subflow; honor pinning if possible, else fallback */
static int schedule_lrtt(struct mptcp_sock *msk, int ifindex)
{
	struct mptcp_subflow_context *subflow, *best = NULL, *best_any = NULL;
	struct sock *ssk;
	u32 rtt, lowest_rtt = ~0U, lowest_any = ~0U;
	bool any = false, matched = false;

	mptcp_for_each_subflow(msk, subflow) {
		ssk = mptcp_subflow_tcp_sock(subflow);

		/* Ensure subflow is active and has buffer space */
		if (!__mptcp_subflow_active(subflow) || !sk_stream_memory_free(ssk))
			continue;

		/* RTT in usec, >>3 from fixed-point */
		rtt = tcp_sk(ssk)->srtt_us >> 3;

		pr_debug("portsched: subflow src=%pI4 dst=%pI4 if=%d rtt=%u us\n",
			 &inet_sk(ssk)->inet_saddr,
			 &inet_sk(ssk)->inet_daddr,
			 ssk->sk_bound_dev_if, rtt);

		any = true;

		/* Track best overall (for fallback) */
		if (rtt < lowest_any) {
			lowest_any = rtt;
			best_any = subflow;
		}

		/* Respect pinning if requested */
		if (ifindex && ssk->sk_bound_dev_if != ifindex)
			continue;

		matched = true;
		if (rtt < lowest_rtt) {
			lowest_rtt = rtt;
			best = subflow;
		}
	}

	if (best) {
		ssk = mptcp_subflow_tcp_sock(best);
		pr_debug("portsched: selected (pinned) src=%pI4 dst=%pI4 rtt=%u us\n",
			 &inet_sk(ssk)->inet_saddr,
			 &inet_sk(ssk)->inet_daddr,
			 lowest_rtt);
		mptcp_subflow_set_scheduled(best, true);
		return 0;
	}

	/* Fallback: if pinning was requested but nothing matched, choose best overall */
	if (ifindex && any && best_any) {
		ssk = mptcp_subflow_tcp_sock(best_any);
		pr_info_ratelimited("portsched: no subflows on ifindex=%d; falling back to best overall.\n",
				    ifindex);
		pr_debug("portsched: selected (fallback) src=%pI4 dst=%pI4 rtt=%u us\n",
			 &inet_sk(ssk)->inet_saddr,
			 &inet_sk(ssk)->inet_daddr,
			 tcp_sk(ssk)->srtt_us >> 3);
		mptcp_subflow_set_scheduled(best_any, true);
		return 0;
	}

	pr_debug("portsched: no usable subflow found\n");
	return -EINVAL;
}

/* ---- Scheduler ops ---- */

static void portsched_init(struct mptcp_sock *msk) { }
static void portsched_release(struct mptcp_sock *msk) { }

/*
 * Your tree’s ops typically expect: int (*get_send)(struct mptcp_sock *)
 * Behavior:
 *   - dport/sport == 5000  -> redundant
 *   - dport/sport == 6060  -> lrtt
 *   - otherwise            -> lrtt (change here if you want to "do nothing")
 */
static int portsched_get_send(struct mptcp_sock *msk)
{
	bool red = is_redundant_mode(msk);
	int ifidx = want_ifindex(msk, red);

	pr_debug("portsched: mode=%s dport=%u sport=%u ifidx=%d\n",
		 red ? "REDUNDANT" : (is_lrtt_mode(msk) ? "LRTT" : "DEFAULT-LRTT"),
		 dport((const struct sock *)msk),
		 sport((const struct sock *)msk),
		 ifidx);

	/* If you only want to act on the two ports and otherwise do nothing,
	 * enable the guard below and return -EAGAIN to let core pick next sched.
	 *
	 * if (!is_redundant_mode(msk) && !is_lrtt_mode(msk))
	 *     return -EAGAIN;
	 */

	return red ? schedule_redundant(msk, ifidx)
		   : schedule_lrtt(msk, ifidx);
}

/* Retransmissions: simple, let core choose the retrans subflow then schedule it */
static int portsched_get_retrans(struct mptcp_sock *msk)
{
	struct sock *ssk = mptcp_subflow_get_retrans(msk);
	if (!ssk)
		return -EINVAL;

	mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
	return 0;
}

static struct mptcp_sched_ops portsched = {
	.name        = "portsched",
	.owner       = THIS_MODULE,
	.init        = portsched_init,
	.release     = portsched_release,
	.get_send    = portsched_get_send,
	.get_retrans = portsched_get_retrans,
};

static int __init portsched_register(void)
{
	return mptcp_register_scheduler(&portsched);
}

static void __exit portsched_unregister(void)
{
	mptcp_unregister_scheduler(&portsched);
}

module_init(portsched_register);
module_exit(portsched_unregister);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("You");
MODULE_DESCRIPTION("MPTCP port-based scheduler (5000→redundant, 6060→lrtt) with optional NIC pinning");
