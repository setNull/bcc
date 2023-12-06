// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#define _GNU_SOURCE
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include "blk_types.h"
#include "mmclatency.h"
#include "mmclatency.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool timestamp;
	bool verbose;
	bool queued;
	bool hwlatency;
} env = {};

static volatile __u64 start_ts;

const char *argp_program_version = "mmclatency 0.1";
const char argp_program_doc[] =
"Trace block I/O.\n"
"\n"
"USAGE: mmclatency\n"
"\n"
"EXAMPLES:\n"
"    mmclatency              # trace all block I/O\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "queued", 'Q', NULL, 0, "Include OS queued time in I/O time" },
	{ "hwlatency", 'H', NULL, 0, "hardware Latency only" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'Q':
		env.queued = true;
		break;
	case 'H':
		env.hwlatency = true;
		break;
	case 't':
		env.timestamp = true;
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void blk_fill_rwbs(char *rwbs, unsigned int op)
{
	int i = 0;

	if (op & REQ_PREFLUSH)
		rwbs[i++] = 'F';

	switch (op & REQ_OP_MASK) {
	case REQ_OP_WRITE:
	case REQ_OP_WRITE_SAME:
		rwbs[i++] = 'W';
		break;
	case REQ_OP_DISCARD:
		rwbs[i++] = 'D';
		break;
	case REQ_OP_SECURE_ERASE:
		rwbs[i++] = 'D';
		rwbs[i++] = 'E';
		break;
	case REQ_OP_FLUSH:
		rwbs[i++] = 'F';
		break;
	case REQ_OP_READ:
		rwbs[i++] = 'R';
		break;
	default:
		rwbs[i++] = 'N';
	}

	if (op & REQ_FUA)
		rwbs[i++] = 'F';
	if (op & REQ_RAHEAD)
		rwbs[i++] = 'A';
	if (op & REQ_SYNC)
		rwbs[i++] = 'S';
	if (op & REQ_META)
		rwbs[i++] = 'M';

	rwbs[i] = '\0';
}

#define BLOCKSIZE 4096 // 对齐磁盘块大小，或者硬件扇区大小
static void direct_io_disk() {
    int fd;
	void *buf;

    if(posix_memalign(&buf, BLOCKSIZE, BLOCKSIZE)) {
        perror("posix_memalign");
        exit(1);
    }

    strncpy(buf, "hello world\n", BLOCKSIZE);

    /* 注意：O_DIRECT不是POSIX标准的一部分，可能并不被所有系统所支持 */
    fd = open("directio.txt", O_WRONLY | O_CREAT | O_DIRECT, 0666);

    if(fd < 0) {
        perror("open");
        exit(1);
    }

    if(write(fd, buf, BLOCKSIZE) != BLOCKSIZE) {
        perror("write");
        exit(1);
    }
    close(fd);
}

#include <sys/ioctl.h>
#include <linux/mmc/ioctl.h>
#include <asm/types.h>

#define MMC_GEN_CMD		56   /* adtc  [31:1] stuff bits. [0]: RD/WR1 R1 */
#define MMC_SEND_EXT_CSD	8	/* adtc				R1  */

/* From kernel linux/mmc/core.h */
#define MMC_RSP_NONE	0			/* no response */
#define MMC_RSP_PRESENT	(1 << 0)
#define MMC_RSP_136	(1 << 1)		/* 136 bit response */
#define MMC_RSP_CRC	(1 << 2)		/* expect valid crc */
#define MMC_RSP_BUSY	(1 << 3)		/* card may send busy */
#define MMC_RSP_OPCODE	(1 << 4)		/* response contains opcode */
#define MMC_CMD_AC	(0 << 5)
#define MMC_CMD_ADTC	(1 << 5)
#define MMC_CMD_BC	(2 << 5)

#define MMC_RSP_SPI_S1	(1 << 7)		/* one status byte */
#define MMC_RSP_SPI_BUSY (1 << 10)		/* card may send busy */

#define MMC_RSP_SPI_R1	(MMC_RSP_SPI_S1)
#define MMC_RSP_SPI_R1B	(MMC_RSP_SPI_S1|MMC_RSP_SPI_BUSY)

#define MMC_RSP_R1	(MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R1B	(MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE|MMC_RSP_BUSY)
static int read_extcsd(int fd, __u8 *ext_csd)
{
	int ret = 0;
	struct mmc_ioc_cmd idata;
	memset(&idata, 0, sizeof(idata));
	memset(ext_csd, 0, sizeof(__u8) * 512);
	idata.write_flag = 0;
	idata.opcode = MMC_SEND_EXT_CSD;
	idata.arg = 0;
	idata.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;
	idata.blksz = 512;
	idata.blocks = 1;
	mmc_ioc_cmd_set_data(idata, ext_csd);

	ret = ioctl(fd, MMC_IOC_CMD, &idata);
	if (ret)
		perror("ioctl");

	return ret;
}

void get_exception_level()
{
	__u8 mmc_ecsd[512] = {0};
	int fd = open("/dev/mmcblk0", O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return;
    }
    if (read_extcsd(fd, mmc_ecsd) < 0)
    {
        goto out;
    }
    printf("0x%02x%02x, %02x ", mmc_ecsd[55], mmc_ecsd[54], mmc_ecsd[246]);
out:
	close(fd);
}

static int flag = 0;
static __u32 pre_status = 0;
static int count = 0;
#define R1_EXCEPTION_EVENT	(1 << 6)	/* sr, a */
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	char rwbs[RWBS_LEN];
	struct timespec ct;
	struct tm *tm;
	char ts[32];

	if (env.timestamp) {
		/* Since `bpf_ktime_get_boot_ns` requires at least 5.8 kernel,
		 * so get time from usespace instead */
		clock_gettime(CLOCK_REALTIME, &ct);
		tm = localtime(&ct.tv_sec);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%-8s.%03ld ", ts, ct.tv_nsec / 1000000);
	} else {
		if (!start_ts) {
			start_ts = e->ts;
		}
		printf("%-11.6f ",(e->ts - start_ts) / 1000000000.0);
	}
	blk_fill_rwbs(rwbs, e->cmd_flags);
	printf("%-14.14s %-7d %-4s %-10lld %-7d ",
		e->comm, e->pid, rwbs, e->sector, e->len);
	if (env.queued)
		printf("%7.3f ", e->qdelta != -1 ? e->qdelta / 1000000.0 : -1);
	if (env.hwlatency)
		printf("%7.3f ", e->hwdelta != -1 ? e->hwdelta / 1000000.0 : -1);
	printf("%7.3f ", e->delta / 1000000.0);

	if((e->status & R1_EXCEPTION_EVENT) && !(pre_status & R1_EXCEPTION_EVENT) ) {
		// bit 6 is 1
		get_exception_level();
	} else {
		printf("%-10s ", " ");	
	}
	pre_status = e->status;
	printf("0x%08x\n", e->status);

	if ( env.queued && e->qdelta != -1 && e->qdelta / 1000000.0  > 10000.0 && !flag) {
//		count += 1;
//		if (count > 40) {
			flag = 1;
			clock_gettime(CLOCK_REALTIME, &ct);
			tm = localtime(&ct.tv_sec);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("before read: %-8s.%03ld\n", ts, ct.tv_nsec / 1000000);
			//read file
			direct_io_disk();
			clock_gettime(CLOCK_REALTIME, &ct);
			tm = localtime(&ct.tv_sec);
			strftime(ts, sizeof(ts), "%H:%M:%S", tm);
			printf("after read: %-8s.%03ld\n", ts, ct.tv_nsec / 1000000);	
			exit(0);
//		}
	} 
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

static void blk_account_io_set_attach_target(struct mmclatency_bpf *obj)
{
	if (fentry_can_attach("blk_account_io_start", NULL))
		bpf_program__set_attach_target(obj->progs.blk_account_io_start,
					       0, "blk_account_io_start");
	else
		bpf_program__set_attach_target(obj->progs.blk_account_io_start,
					       0, "__blk_account_io_start");
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct ksyms *ksyms = NULL;
	struct mmclatency_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	obj = mmclatency_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}


	obj->rodata->targ_queued = env.queued;
	obj->rodata->targ_mmc_started = env.hwlatency;

	blk_account_io_set_attach_target(obj);

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}
	if (!ksyms__get_symbol(ksyms, "blk_account_io_merge_bio"))
		bpf_program__set_autoload(obj->progs.blk_account_io_merge_bio, false);
	if (!env.queued)
		bpf_program__set_autoload(obj->progs.block_rq_insert, false);
	if (!env.hwlatency) {
		bpf_program__set_autoload(obj->progs.mmc_request_start, false);
		bpf_program__set_autoload(obj->progs.mmc_request_done, false);
	}
	//bpf_program__set_autoload(obj->progs.mmc_request_start, false);

	err = mmclatency_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = mmclatency_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (env.timestamp) {
		printf("%-12s ", "TIMESTAMP");
	} else {
		printf("%-11s ", "TIME(s)");
	}
	printf("%-14s %-7s %-4s %-10s %-7s ",
		"COMM", "PID", "T", "SECTOR", "BYTES");
	if (env.queued)
		printf("%-7s ", "QUE(ms)");
	if (env.hwlatency)
		printf("%-7s ", "HWLAT(ms)");
	printf("%-7s ", "LAT(ms)");
	if (env.hwlatency) {
		printf("%-10s ", "ex_level");
		printf("%-10s\n", "device_status");
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	/* main: poll */
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	mmclatency_bpf__destroy(obj);
	ksyms__free(ksyms);
	return err != 0;
}
