/* SPDX-License-Identifier: Apache-2.0 */
/* Run only in an isolated BPF-LSM-enabled VM. Loading must never fall back
 * to telemetry-only; every program must load and attach successfully. */
#include <stdio.h>
#include <sys/resource.h>
#include "xsypher.skel.h"

int main(void)
{
    struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &limit)) {
        perror("setrlimit");
        return 1;
    }
    struct xsypher_bpf *skel = xsypher_bpf__open_and_load();
    if (!skel)
        return 1;
    int err = xsypher_bpf__attach(skel);
    if (err)
        fprintf(stderr, "attach failed: %d\n", err);
    xsypher_bpf__destroy(skel);
    return err ? 1 : 0;
}
