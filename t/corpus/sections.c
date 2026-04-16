/* One tiny program per row of the section-name table in src/prog.rs.
 *
 * libbpf decides a program's type from the name of the section it is in, and
 * libbpf is the only thing on this machine that can say whether our copy of
 * that table is right. The rest of the corpus puts every program in
 * `socket/...`, which libbpf maps to no type at all, so before this file
 * existed exactly zero rows had an oracle.
 *
 * The bodies are deliberately trivial. Nothing here is about instructions;
 * these exist so `bpf_program__type` has something to be compared against.
 * The suite asserts that every row of the table is the row prog_type would
 * pick for one of these sections, so a row added without a program here
 * turns it red: a table entry nothing exercises may say anything.
 *
 * Rows libbpf matches as a prefix are given a `/zz` tail, which is how the
 * difference between the two kinds of row is exercised rather than assumed.
 */
#include "bpf.h"

#define PROG(sec, fn)                                                         \
    SEC(sec)                                                                  \
    int fn(void *ctx)                                                         \
    {                                                                         \
        return (int)(u64)ctx;                                                 \
    }

PROG("socket", p_socket)
PROG("sk_reuseport/migrate", p_sk_reuseport_migrate)
PROG("sk_reuseport", p_sk_reuseport)
PROG("kprobe/zz", p_kprobe)
PROG("kretprobe/zz", p_kretprobe)
PROG("kprobe.multi/zz", p_kprobe_multi)
PROG("kretprobe.multi/zz", p_kretprobe_multi)
PROG("kprobe.session/zz", p_kprobe_session)
PROG("uprobe/zz", p_uprobe)
PROG("uretprobe/zz", p_uretprobe)
PROG("uprobe.s/zz", p_uprobe_s)
PROG("uretprobe.s/zz", p_uretprobe_s)
PROG("uprobe.multi/zz", p_uprobe_multi)
PROG("uretprobe.multi/zz", p_uretprobe_multi)
PROG("usdt/zz", p_usdt)
PROG("usdt.s/zz", p_usdt_s)
PROG("tracepoint/zz", p_tracepoint)
PROG("tp/zz", p_tp)
PROG("raw_tracepoint/zz", p_raw_tracepoint)
PROG("raw_tp/zz", p_raw_tp)
PROG("raw_tracepoint.w/zz", p_raw_tracepoint_w)
PROG("raw_tp.w/zz", p_raw_tp_w)
PROG("xdp.frags/devmap", p_xdp_frags_devmap)
PROG("xdp/devmap", p_xdp_devmap)
PROG("xdp.frags/cpumap", p_xdp_frags_cpumap)
PROG("xdp/cpumap", p_xdp_cpumap)
PROG("xdp.frags", p_xdp_frags)
PROG("xdp", p_xdp)
PROG("perf_event", p_perf_event)
PROG("lwt_in", p_lwt_in)
PROG("lwt_out", p_lwt_out)
PROG("lwt_xmit", p_lwt_xmit)
PROG("lwt_seg6local", p_lwt_seg6local)
PROG("lirc_mode2", p_lirc_mode2)
PROG("cgroup_skb/ingress", p_cgroup_skb_ingress)
PROG("cgroup_skb/egress", p_cgroup_skb_egress)
PROG("cgroup/skb", p_cgroup_skb)
PROG("cgroup/sock_create", p_cgroup_sock_create)
PROG("cgroup/sock_release", p_cgroup_sock_release)
PROG("cgroup/sock", p_cgroup_sock)
PROG("cgroup/post_bind4", p_cgroup_post_bind4)
PROG("cgroup/post_bind6", p_cgroup_post_bind6)
PROG("cgroup/dev", p_cgroup_dev)
PROG("cgroup/sysctl", p_cgroup_sysctl)
PROG("cgroup/getsockopt", p_cgroup_getsockopt)
PROG("cgroup/setsockopt", p_cgroup_setsockopt)
PROG("cgroup/bind4", p_cgroup_bind4)
PROG("cgroup/bind6", p_cgroup_bind6)
PROG("cgroup/connect4", p_cgroup_connect4)
PROG("cgroup/connect6", p_cgroup_connect6)
PROG("cgroup/connect_unix", p_cgroup_connect_unix)
PROG("cgroup/sendmsg4", p_cgroup_sendmsg4)
PROG("cgroup/sendmsg6", p_cgroup_sendmsg6)
PROG("cgroup/recvmsg4", p_cgroup_recvmsg4)
PROG("cgroup/recvmsg6", p_cgroup_recvmsg6)
PROG("cgroup/getpeername4", p_cgroup_getpeername4)
PROG("cgroup/getpeername6", p_cgroup_getpeername6)
PROG("cgroup/getsockname4", p_cgroup_getsockname4)
PROG("cgroup/getsockname6", p_cgroup_getsockname6)
PROG("sockops", p_sockops)
PROG("sk_skb/stream_parser", p_sk_skb_stream_parser)
PROG("sk_skb/stream_verdict", p_sk_skb_stream_verdict)
PROG("sk_skb", p_sk_skb)
PROG("sk_msg", p_sk_msg)
PROG("classifier", p_classifier)
PROG("tc/ingress", p_tc_ingress)
PROG("tc/egress", p_tc_egress)
PROG("tc", p_tc)
PROG("tcx/ingress", p_tcx_ingress)
PROG("tcx/egress", p_tcx_egress)
PROG("netkit/primary", p_netkit_primary)
PROG("netkit/peer", p_netkit_peer)
PROG("action", p_action)
PROG("sk_lookup", p_sk_lookup)
PROG("flow_dissector", p_flow_dissector)
PROG("syscall", p_syscall)
PROG("netfilter", p_netfilter)
PROG("lsm/zz", p_lsm)
PROG("lsm.s/zz", p_lsm_s)
PROG("fentry/zz", p_fentry)
PROG("fexit/zz", p_fexit)
PROG("fmod_ret/zz", p_fmod_ret)
PROG("fentry.s/zz", p_fentry_s)
PROG("fexit.s/zz", p_fexit_s)
PROG("fmod_ret.s/zz", p_fmod_ret_s)
PROG("tp_btf/zz", p_tp_btf)
PROG("iter/zz", p_iter)
PROG("iter.s/zz", p_iter_s)
PROG("freplace/zz", p_freplace)
PROG("struct_ops/zz", p_struct_ops)
PROG("struct_ops.s/zz", p_struct_ops_s)

LICENSE("GPL");
