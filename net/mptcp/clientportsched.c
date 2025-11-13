// SPDX-License-Identifier: GPL-2.0
/*
 * MPTCP "portsched" — source-port selector that dispatches to your
 * proven LRTT and Redundant schedulers without altering their logic.
 *
 * Client SOURCE port decides mode:
 *   5000 -> REDUNDANT (your code path)
 *   6060 -> LRTT     (your NEW code below)
 *   else -> return -EAGAIN (let core/next scheduler handle it)
 *
 * Notes:
 * - We keep Redundant identical to your working logic.
 * - LRTT logic replaced with your new version (anti-overbuffering + fallback).
 * - Retrans mirrors each mode's behavior.
 * - A netdevice notifier logs IF-up events (can be extended later).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include <net/inet_connection_sock.h>
#include "protocol.h"

#ifndef pr_fmt
#define pr_fmt(fmt) "MPTCP-PORTSCHED: " fmt
#endif

/* Trigger ports (CLIENT SOURCE PORT) */
#define PORT_REDUNDANT 5000
#define PORT_LRTT      6060

/* --- Tiny helpers --- */
static inline u16 dport(const struct sock *sk) { return ntohs(inet_sk(sk)->inet_dport); }
static inline u16 sport(const struct sock *sk) { return ntohs(inet_sk(sk)->inet_sport); }

/* ===========================================================
 * ================  REDUNDANT (your logic)  =================
 * =========================================================== */

static int redundant_like_yours_get_send(struct mptcp_sock *msk)
{
	struct mptcp_subflow_context *subflow;
	bool scheduled = false;

	msk_owned_by_me(msk);

	mptcp_for_each_subflow(msk, subflow) {
		if (!mptcp_subflow_active(subflow))
			continue;

		if (!__tcp_can_send(subflow->tcp_sock) ||
		    !sk_stream_memory_free(subflow->tcp_sock)) {
			pr_debug("Redundant: Skipping subflow (not writable)");
			continue;
		}

		mptcp_subflow_set_scheduled(subflow, true);
		scheduled = true;

		pr_info("Redundant: Scheduling subflow on ifindex=%d\n",
			subflow->tcp_sock->sk_bound_dev_if);
	}

	return scheduled ? 0 : -EINVAL;
}

static int redundant_like_yours_get_retrans(struct mptcp_sock *msk)
{
	/* Redundant retransmits the same way */
	return redundant_like_yours_get_send(msk);
}

/* ===========================================================
 * ===================  NEW LRTT LOGIC  ======================
 *  - Prefer lowest RTT subflow that can send now
 *  - Skip paths with ~> 2*BDP queued-but-unsent
 *  - Fallback to kernel helper if nothing matches
 * =========================================================== */

/* prefer non-backup on ties */
static inline bool lrtt_better_tie(struct mptcp_subflow_context *cur,
				   struct mptcp_subflow_context *cand)
{
	return cur && cur->backup && !cand->backup;
}

static int lrtt_new_get_send(struct mptcp_sock *msk)
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

		/* Portable anti-overbuffering guard: skip if not-sent > ~2*BDP */
		tp = tcp_sk(ssk);
		if ((tp->write_seq - tp->snd_nxt) > 2U * tp->snd_cwnd * tp->advmss)
			continue;

		/* RTT in usec, >>3 from fixed-point */
		rtt = tp->srtt_us >> 3;

		pr_info("LRTT: Subflow src=%pI4 dst=%pI4 rtt=%u us cwnd=%u snd_wnd=%u notsent=%u\n",
			&inet_sk(ssk)->inet_saddr, &inet_sk(ssk)->inet_daddr,
			rtt, tp->snd_cwnd, tp->snd_wnd,
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
		ssk = mptcp_subflow_tcp_sock(best);
		pr_info("LRTT: Selected src=%pI4 dst=%pI4 rtt=%u us\n",
			&inet_sk(ssk)->inet_saddr, &inet_sk(ssk)->inet_daddr,
			lowest_rtt);
		return 0; /* success */
	}

	/* Fallback to the kernel’s default helper (same as default scheduler) */
	ssk = mptcp_subflow_get_send(msk);
	if (ssk) {
		mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
		pr_info("LRTT: Fallback(default) via src=%pI4 dst=%pI4\n",
			&inet_sk(ssk)->inet_saddr, &inet_sk(ssk)->inet_daddr);
		return 0;
	}

	pr_info("LRTT: No usable subflow found\n");
	return -EINVAL;
}

static int lrtt_new_get_retrans(struct mptcp_sock *msk)
{
	struct sock *ssk = mptcp_subflow_get_retrans(msk);
	if (!ssk)
		return -EINVAL;

	mptcp_subflow_set_scheduled(mptcp_subflow_ctx(ssk), true);
	pr_info("LRTT: Retrans via src=%pI4 dst=%pI4\n",
		&inet_sk(ssk)->inet_saddr, &inet_sk(ssk)->inet_daddr);
	return 0;
}

/* -------- IF-up notifier from your new LRTT code -------- */
static int portsched_netdev_event(struct notifier_block *nb, unsigned long ev, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (ev != NETDEV_UP && ev != NETDEV_CHANGE && ev != NETDEV_CHANGEADDR)
		return NOTIFY_DONE;

	if (!netif_oper_up(dev))
		return NOTIFY_DONE;

	pr_info("IF-UP: %s (index=%d) is up — PM may recreate subflows\n",
		dev->name, dev->ifindex);
	return NOTIFY_OK;
}

static struct notifier_block portsched_nb = {
	.notifier_call = portsched_netdev_event,
};

/* ===========================================================
 * ===================  Glue scheduler  ======================
 * =========================================================== */

static void portsched_init(struct mptcp_sock *msk) { }
static void portsched_release(struct mptcp_sock *msk) { }

static int portsched_get_send(struct mptcp_sock *msk)
{
	const struct sock *sk = (const struct sock *)msk;
	u16 sp = sport(sk);

	/* Only act on our trigger ports; avoid affecting other sockets */
	if (sp != PORT_REDUNDANT && sp != PORT_LRTT)
		return -EAGAIN;

	if (sp == PORT_REDUNDANT) {
		pr_info_ratelimited("MODE=REDUNDANT sp=%u dp=%u\n", sp, dport(sk));
		return redundant_like_yours_get_send(msk);
	} else {
		pr_info_ratelimited("MODE=LRTT sp=%u dp=%u\n", sp, dport(sk));
		return lrtt_new_get_send(msk);
	}
}

static int portsched_get_retrans(struct mptcp_sock *msk)
{
	const struct sock *sk = (const struct sock *)msk;
	u16 sp = sport(sk);

	if (sp == PORT_REDUNDANT)
		return redundant_like_yours_get_retrans(msk);
	else if (sp == PORT_LRTT)
		return lrtt_new_get_retrans(msk);

	/* For non-trigger sockets, defer to next scheduler */
	return -EAGAIN;
}

/* Registration */
static struct mptcp_sched_ops portsched = {
	.name        = "clientportsched",
	.owner       = THIS_MODULE,
	.init        = portsched_init,
	.release     = portsched_release,
	.get_send    = portsched_get_send,
	.get_retrans = portsched_get_retrans,
};

static int __init portsched_register(void)
{
	int ret;

	ret = mptcp_register_scheduler(&portsched);
	if (ret)
		return ret;

	ret = register_netdevice_notifier(&portsched_nb);
	if (ret) {
		mptcp_unregister_scheduler(&portsched);
		return ret;
	}

	pr_info("registered (modes: 5000=Redundant, 6060=LRTT, else=pass)\n");
	return 0;
}

static void __exit portsched_unregister(void)
{
	unregister_netdevice_notifier(&portsched_nb);
	mptcp_unregister_scheduler(&portsched);
}

module_init(portsched_register);
module_exit(portsched_unregister);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("You");
MODULE_DESCRIPTION("MPTCP source-port selector: 5000→Redundant, 6060→NEW LRTT (anti-overbuffering + fallback)");
