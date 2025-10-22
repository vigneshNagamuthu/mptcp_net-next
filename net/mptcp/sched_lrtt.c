// SPDX-License-Identifier: GPL-2.0
/*
 * LRTT (Lowest RTT First) MPTCP scheduler
 * - Prefer lowest-RTT subflow that can actually send now
 * - Skip heavily backlogged paths (~2*BDP queued but unsent)
 * - Fallback to kernel helper if none match (same behavior as "default")
 * - Return 0 on success, -EINVAL only if truly nothing is schedulable
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/mptcp.h>
#include <net/tcp.h>              /* tcp_sk(), __tcp_can_send() */
#include "protocol.h"

#ifndef pr_fmt
#define pr_fmt(fmt) "MPTCP-LRTT: " fmt
#endif

/* Optional: prefer non-backup subflows on ties */
static inline bool lrtt_better_tie(struct mptcp_subflow_context *cur,
				   struct mptcp_subflow_context *cand)
{
	return cur && cur->backup && !cand->backup;
}

static int lrtt_get_send(struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow, *best = NULL;
	struct sock *ssk;
	struct tcp_sock *tp;
	u32 rtt, lowest_rtt = ~0U;

	/* Pick the lowest-RTT subflow that can actually send now */
	mptcp_for_each_subflow(msk, subflow) {
		ssk = mptcp_subflow_tcp_sock(subflow);

		/* Must be active, have write memory, and be allowed to send by TCP */
		if (!__mptcp_subflow_active(subflow) ||
		    !sk_stream_memory_free(ssk) ||
		    !__tcp_can_send(ssk))
			continue;

		/* Portable anti-overbuffering guard:
		 * skip paths already holding > ~2*BDP of not-sent data
		 * (write_seq - snd_nxt is queued-but-unsent)
		 */
		tp = tcp_sk(ssk);
		if ((tp->write_seq - tp->snd_nxt) > 2U * tp->snd_cwnd * tp->advmss)
			continue;

		/* RTT in usec, >>3 from fixed-point */
		rtt = tp->srtt_us >> 3;

		pr_info("Subflow: src=%pI4 dst=%pI4 rtt=%u us cwnd=%u snd_wnd=%u notsent=%u\n",
			 &inet_sk(ssk)->inet_saddr, &inet_sk(ssk)->inet_daddr,
			 rtt, tp->snd_cwnd, tcp_sk(ssk)->snd_wnd,
			 (unsigned)(tp->write_seq - tp->snd_nxt));

		/* Lowest RTT wins; on ties, prefer non-backup */
		if (rtt < lowest_rtt ||
		    (rtt == lowest_rtt && lrtt_better_tie(best, subflow))) {
			lowest_rtt = rtt;
			best = subflow;
		}
	}

	if (best) {
		mptcp_subflow_set_scheduled(best, true);
		pr_info("Selected: src=%pI4 dst=%pI4 rtt=%u us\n",
			 &inet_sk(mptcp_subflow_tcp_sock(best))->inet_saddr,
			 &inet_sk(mptcp_subflow_tcp_sock(best))->inet_daddr,
			 lowest_rtt);
		return 0; /* success */
	}

	/* Fallback to the kernel’s default helper (same one the default scheduler uses) */
	ssk = mptcp_subflow_get_send(msk);
	if (ssk) {
		mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
		pr_info("Fallback(default): src=%pI4 dst=%pI4\n",
			 &inet_sk(ssk)->inet_saddr, &inet_sk(ssk)->inet_daddr);
		return 0; /* success via default logic */
	}

	/* Truly nothing usable this round */
	pr_info("No usable subflow found\n");
	return -EINVAL;
}

/* Optional: mirror default behavior for retransmissions */
static int lrtt_get_retrans(struct mptcp_sock *msk)
{
	struct sock *ssk = mptcp_subflow_get_retrans(msk);
	if (!ssk)
		return -EINVAL;

	mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
	pr_info("Retrans via: src=%pI4 dst=%pI4\n",
		 &inet_sk(ssk)->inet_saddr, &inet_sk(ssk)->inet_daddr);
	return 0;
}

static struct mptcp_sched_ops lrtt_sched = {
	.get_send    = lrtt_get_send,
	.get_retrans = lrtt_get_retrans,   /* comment out if you prefer default routing */
	.name        = "lrtt",
	.owner       = THIS_MODULE,
};

// --- NEW ---
// Simple notifier to detect when interfaces come back up.
// This does not recreate subflows by itself — it only logs and can later
// call PM helpers if you wish to extend it.
static int lrtt_netdev_event(struct notifier_block *nb, unsigned long ev, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (ev != NETDEV_UP && ev != NETDEV_CHANGE && ev != NETDEV_CHANGEADDR)
		return NOTIFY_DONE;

	if (!netif_oper_up(dev))
		return NOTIFY_DONE;

	pr_info("Interface %s (index=%d) is up — MPTCP PM should recreate subflows\n",
		dev->name, dev->ifindex);

	/* You could later add:
	 *   mptcp_pm_nl_add_addr(...);
	 *   mptcp_pm_nl_create_subflow(...);
	 * if these functions are exported.
	 */
	return NOTIFY_OK;
}

static struct notifier_block lrtt_nb = {
	.notifier_call = lrtt_netdev_event,
};
// --- END NEW ---

static int __init lrtt_register(void)
{
	int ret = mptcp_register_scheduler(&lrtt_sched);
	if (!ret)
		pr_info("registered\n");

	// --- NEW ---
	ret = register_netdevice_notifier(&lrtt_nb);
	if (ret) {
		mptcp_unregister_scheduler(&lrtt_sched);
		return ret;
	}
	pr_info("registered (with IF-up recovery notifier)\n");
	// --- END NEW ---

	return ret;
}

static void __exit lrtt_unregister(void)
{
	unregister_netdevice_notifier(&lrtt_nb);
	mptcp_unregister_scheduler(&lrtt_sched);
}

module_init(lrtt_register);
module_exit(lrtt_unregister);

MODULE_AUTHOR("Nathaneal");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Lowest RTT First (LRTT) MPTCP scheduler");
