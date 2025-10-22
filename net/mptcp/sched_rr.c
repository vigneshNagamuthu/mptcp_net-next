// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <net/mptcp.h>
#include "protocol.h"

#define MAX_SUBFLOWS 8

static int rr_get_send(struct mptcp_sock *msk)
{
    struct mptcp_subflow_context *subflow;
    struct sock *ssk;
    static u32 rr_index = 0;
    int count = 0;

    mptcp_for_each_subflow(msk, subflow) {
        count++;
    }

    if (count == 0) {
        pr_info("RR: No subflows available\n");
        return -EINVAL;
    }

    int index = rr_index;
    rr_index = (rr_index + 1) % count;

    int i = 0;
    mptcp_for_each_subflow(msk, subflow) {
        if (i++ < index) continue;

        ssk = mptcp_subflow_tcp_sock(subflow);
        bool active = __mptcp_subflow_active(subflow);
        bool mem_ok = sk_stream_memory_free(ssk);

        pr_info("RR-Check (1st pass): ifindex=%d active=%d mem_free=%d\n",
                ssk->sk_bound_dev_if, active, mem_ok);

        if (active && mem_ok) {
            struct inet_sock *inet = inet_sk(ssk);
            pr_info("RR-Selected (1st pass): ifindex=%d idx=%d src=%pI4:%u dst=%pI4:%u\n",
                ssk->sk_bound_dev_if, index,
                &inet->inet_saddr, ntohs(inet->inet_sport),
                &inet->inet_daddr, ntohs(inet->inet_dport));
            mptcp_subflow_set_scheduled(subflow, true);
            return 0;
        }
    }

    // Retry all subflows in case one recovered
    pr_info("RR: No subflow selected on first pass, retrying all subflows\n");

    mptcp_for_each_subflow(msk, subflow) {
        ssk = mptcp_subflow_tcp_sock(subflow);
        bool active = __mptcp_subflow_active(subflow);
        bool mem_ok = sk_stream_memory_free(ssk);

        pr_info("RR-Check (recovery): ifindex=%d active=%d mem_free=%d\n",
                ssk->sk_bound_dev_if, active, mem_ok);

        if (active && mem_ok) {
            struct inet_sock *inet = inet_sk(ssk);
            pr_info("RR-Selected (recovery): ifindex=%d src=%pI4:%u dst=%pI4:%u\n",
                ssk->sk_bound_dev_if,
                &inet->inet_saddr, ntohs(inet->inet_sport),
                &inet->inet_daddr, ntohs(inet->inet_dport));
            mptcp_subflow_set_scheduled(subflow, true);
            return 0;
        } else if (!active) {
            pr_info("RR-Recovery: Skipping inactive subflow ifindex=%d\n",
                    ssk->sk_bound_dev_if);
        }
    }

    pr_info("RR: No usable subflow even after recovery\n");
    return -EINVAL;
}

static int rr_get_retrans(struct mptcp_sock *msk)
{
	return rr_get_send(msk);
}

static void rr_init(struct mptcp_sock *msk) { }
static void rr_release(struct mptcp_sock *msk) { }

static struct mptcp_sched_ops mptcp_rr_sched = {
	.get_send    = rr_get_send,
	.get_retrans = rr_get_retrans,
	.init        = rr_init,
	.release     = rr_release,
	.name        = "rrpacket",
	.owner       = THIS_MODULE,
};

static int __init rr_register(void)
{
	return mptcp_register_scheduler(&mptcp_rr_sched);
}

static void __exit rr_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_rr_sched);
}

module_init(rr_register);
module_exit(rr_unregister);

MODULE_AUTHOR("ChatGPT");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fixed Round-Robin Packet-Based MPTCP Scheduler");
