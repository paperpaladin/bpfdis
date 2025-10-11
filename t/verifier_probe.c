/* Is the kernel verifier reachable from here?
 *
 * The question matters because a refusal for lack of privilege is not a
 * rejection by the verifier, and nothing in this repository may count one as
 * the other. The probe answers it by loading two programs: one the verifier
 * cannot reject (`r0 = 0; exit`) and one it must reject (an instruction
 * stream that falls off the end with no `exit`). If both come back with the
 * same errno, the syscall never reached the verifier and the outcome says
 * nothing about either program.
 *
 * Prints exactly one VERIFIER: line. Exit 0 either way: a blocked oracle is a
 * measured fact, not a test failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif
#define BPF_PROG_LOAD 5
#define BPF_PROG_TYPE_SOCKET_FILTER 1

struct insn {
    uint8_t code;
    uint8_t regs;
    int16_t off;
    int32_t imm;
};

/* The first fields of union bpf_attr's prog-load arm, in order. Declared here
 * rather than included, because <linux/bpf.h> is not reachable for every
 * target this tree compiles for and the layout of the prefix is stable ABI. */
struct prog_attr {
    uint32_t prog_type;
    uint32_t insn_cnt;
    uint64_t insns;
    uint64_t license;
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buf;
    uint32_t kern_version;
    uint32_t prog_flags;
    char prog_name[16];
    uint32_t prog_ifindex;
    uint32_t expected_attach_type;
    uint32_t attach_btf_id;
    uint32_t attach_prog_fd;
    uint32_t func_info_rec_size;
    uint64_t func_info;
    uint32_t func_info_cnt;
    uint32_t line_info_rec_size;
    uint64_t line_info;
    uint32_t line_info_cnt;
    uint32_t attach_btf_obj_fd;
    uint32_t core_relo_cnt;
    uint64_t fd_array;
    uint64_t core_relos;
    uint32_t core_relo_rec_size;
    uint32_t log_true_size;
    uint8_t pad[64];
};

static int load(struct insn *ins, int n, char *log, int logsz)
{
    struct prog_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insn_cnt = (uint32_t)n;
    a.insns = (uint64_t)(uintptr_t)ins;
    a.license = (uint64_t)(uintptr_t)"GPL";
    if (log) {
        a.log_level = 1;
        a.log_size = (uint32_t)logsz;
        a.log_buf = (uint64_t)(uintptr_t)log;
        log[0] = 0;
    }
    errno = 0;
    return (int)syscall(__NR_bpf, BPF_PROG_LOAD, &a, sizeof a);
}

int main(void)
{
    static char log[16384];
    struct insn good[2];
    struct insn bad[1];
    int fd_good, e_good, fd_bad, e_bad;

    memset(good, 0, sizeof good);
    good[0].code = 0xb7; /* r0 = 0 */
    good[1].code = 0x95; /* exit    */
    memset(bad, 0, sizeof bad);
    bad[0].code = 0xb7; /* r0 = 0, and then nothing: no exit */

    fd_good = load(good, 2, log, sizeof log);
    e_good = errno;
    fd_bad = load(bad, 1, NULL, 0);
    e_bad = errno;
    if (fd_good >= 0)
        close(fd_good);
    if (fd_bad >= 0)
        close(fd_bad);

    if (fd_good >= 0 && fd_bad < 0) {
        printf("VERIFIER: reachable (valid program loaded; invalid refused with"
               " errno %d %s)\n", e_bad, strerror(e_bad));
        return 0;
    }
    if (fd_good >= 0 && fd_bad >= 0) {
        printf("VERIFIER: BROKEN (a program with no exit instruction loaded;"
               " this kernel is not a usable oracle)\n");
        return 0;
    }
    if (e_good == e_bad) {
        printf("VERIFIER: BLOCKED errno=%d %s (a program the verifier cannot"
               " reject gets the same errno as one it must reject, so the"
               " syscall did not reach the verifier)\n", e_good, strerror(e_good));
        return 0;
    }
    printf("VERIFIER: PARTIAL valid=%d/%s invalid=%d/%s\n", e_good,
           strerror(e_good), e_bad, strerror(e_bad));
    return 0;
}
