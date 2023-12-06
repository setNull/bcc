// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "mmclatency.h"
#include "core_fixes.bpf.h"

#define MAX_ENTRIES	5120

extern __u32 LINUX_KERNEL_VERSION __kconfig;
const volatile bool targ_queued = false;
const volatile bool targ_mmc_started = false;

struct piddata {
	char comm[TASK_COMM_LEN];
	u32 pid;
};
struct stage {
	u64 insert;
	u64 issue;
	u64 mmcstart;
	u64 mmcdone;
	u32 device_status;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, struct stage);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, struct piddata);
} infobyreq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline
int trace_pid(struct request *rq)
{
	u64 id = bpf_get_current_pid_tgid();
	struct piddata piddata = {};
	struct piddata *piddatap;
	piddatap = bpf_map_lookup_elem(&infobyreq, &rq);
	if (!piddatap) {
		piddatap = &piddata;
	} else {
		bpf_printk("request in map, prev comm %s\n", piddatap->comm);
		return 0;
	}
	piddatap->pid = id >> 32;
	bpf_get_current_comm(&piddatap->comm, sizeof(&piddatap->comm));
	if(piddatap == &piddata)
		bpf_map_update_elem(&infobyreq, &rq, piddatap, 0);
	return 0;
}

SEC("kprobe/blk_account_io_start")
int BPF_PROG(blk_account_io_start, struct request *rq)
{
	return trace_pid(rq);
}

SEC("kprobe/blk_account_io_merge_bio")
int BPF_KPROBE(blk_account_io_merge_bio, struct request *rq)
{
	return trace_pid(rq);
}


/*
SEC("kprobe/sdhci_irq")
int BPF_KPROBE(sdhci_irq, int irq, void * dev_id)
{
	struct mmc_request * mrqs_done[2] = {0};
	struct sdhci_host * host = dev_id;
	mrqs_done[0] = host->mrqs_done[0];
	mrqs_done[1] = host->mrqs_done[1];
	bpf_printk("wangjie test %lld\n", BPF_CORE_READ(req, __sector));	
	return 0;
}
*/

static __always_inline
int trace_rq_start(struct request *rq, enum ACTION action, u32 cmd_resp)
{
	struct stage *stagep, stage = {};
	u64 ts = bpf_ktime_get_ns();
	stagep = bpf_map_lookup_elem(&start, &rq);
	if (!stagep) {
		stagep = &stage;
	}
	switch (action) {
	case INSERT:
		stagep->insert = ts;
		break;
	case ISSUE:
		stagep->issue = ts;	
		break;
	case MMCSTART:
		stagep->mmcstart = ts;	
		break;
	case MMCDONE:
		stagep->mmcdone = ts;
		stagep->device_status = cmd_resp;
		break;
	default:
		bpf_printk("action not support\n");	
	}
	if (stagep == &stage)
		bpf_map_update_elem(&start, &rq, stagep, 0);
	return 0;
}

/*
SEC("kprobe/sdhci_send_command")
int BPF_KPROBE(sdhci_send_command, struct sdhci_host *host, struct mmc_command *cmd)
{
	struct mmc_request * mrq = BPF_CORE_READ(cmd, mrq);
	//struct mmc_queue_req *mqrq = container_of(mrq, struct mmc_queue_req, brq.mrq);
	//struct request *req = (void *)mqrq - sizeof(struct request);
	bpf_printk("wangjie test %d\n", BPF_CORE_READ(mrq, tag));	
	return 0;//trace_rq_start((void *)req, MMCSTART);
}
*/

SEC("tp_btf/block_rq_insert")
int BPF_PROG(block_rq_insert)
{
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 11, 0))
		return trace_rq_start((void *)ctx[0], INSERT, 0);
	else
		return trace_rq_start((void *)ctx[1], INSERT, 0);
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue)
{
	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 11, 0))
		return trace_rq_start((void *)ctx[0], ISSUE, 0);
	else
		return trace_rq_start((void *)ctx[1], ISSUE, 0);
}

SEC("tp_btf/mmc_request_start")
int BPF_PROG(mmc_request_start)
{
	//bpf_printk("wangjie test in mmc start\n");
	struct mmc_queue_req *mqrq = container_of(ctx[1], struct mmc_queue_req,
						  brq.mrq);
	struct request *req = (void *)mqrq - sizeof(struct request);
	return trace_rq_start((void *)req, MMCSTART, 0);
}

SEC("tp_btf/mmc_request_done")
int BPF_PROG(mmc_request_done)
{
	//bpf_printk("wangjie test in mmc done\n");
	struct mmc_queue_req *mqrq = container_of(ctx[1], struct mmc_queue_req,
						  brq.mrq);
	struct request *req = (void *)mqrq - sizeof(struct request);

	struct mmc_command *cmd = ((struct mmc_request *)ctx[1])->cmd;
	u32 cmd_resp_0 = cmd ? cmd->resp[0] : 0;
	return trace_rq_start((void *)req, MMCDONE, cmd_resp_0);
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error,
	     unsigned int nr_bytes)
{
	u64 ts = bpf_ktime_get_ns();
	struct stage *stagep;
	struct piddata *piddatap;
	struct event event = {};
	s64 delta;

	stagep = bpf_map_lookup_elem(&start, &rq);
	if (!stagep){
		return 0;
	}
	delta = (s64)(ts - stagep->issue);
	if (delta < 0)
		goto cleanup;
	piddatap = bpf_map_lookup_elem(&infobyreq, &rq);
	if (!piddatap){
		event.comm[0] = '?';
	} else {
		__builtin_memcpy(&event.comm, piddatap->comm, sizeof(event.comm));
		event.pid = piddatap->pid;
	}
	event.delta = delta;
	if (targ_queued && BPF_CORE_READ(rq, q, elevator)) {
		if (!stagep->insert)
			event.qdelta = -1; /* missed or don't insert entry */
		else
			event.qdelta = stagep->issue - stagep->insert;
	}
	if (targ_mmc_started) {
		if (!stagep->mmcstart || !stagep->mmcdone)
			event.hwdelta = -1; /* missed or don't use emmc */
		else {
			event.hwdelta = stagep->mmcdone - stagep->mmcstart;
			event.status = stagep->device_status;
		}
	}
	event.ts = ts;
	event.sector = BPF_CORE_READ(rq, __sector);
	event.len = BPF_CORE_READ(rq, __data_len);
	event.cmd_flags = BPF_CORE_READ(rq, cmd_flags);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
			sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &rq);
	bpf_map_delete_elem(&infobyreq, &rq);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
