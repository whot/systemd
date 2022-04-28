/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdint.h>
#include <unistd.h>

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8192);
        __type(key, struct hidraw_list *);
        __type(value, uint8_t);
} authorized_files SEC(".maps");

struct file {
        void *private_data;
} __attribute__((preserve_access_index));

int foreground = 1;

SEC("fexit/hidraw_open")
int BPF_PROG(hidraw_open, struct inode *inode, struct file *file, int ret)
{
        const uint8_t revoked = 0;
        struct hidraw_list *list = file->private_data;

        if (ret)
                return 0;

        /* not in foreground, don't care */
        if (!foreground)
                return 0;

        /* store the id in the allowed list */
        bpf_map_update_elem(&authorized_files, &list, &revoked, BPF_ANY);

        return 0;
}

SEC("fentry/hidraw_release")
int BPF_PROG(hidraw_release, struct inode *inode, struct file *file)
{
        struct hidraw_list *list = file->private_data;

        /* not in foreground, don't care */
        if (!foreground)
                return 0;

        /* the file has been closed, we can clean up */
        bpf_map_delete_elem(&authorized_files, &list);

        return 0;
}

static int is_revoked(struct hidraw_list *list)
{
        uint8_t *revoked;

        /* first check if the file is in our list */
        revoked = bpf_map_lookup_elem(&authorized_files, &list);

        /* not part of our list, abort */
        if (!revoked)
                return 0;

        /* we are not in foreground, the file is revoked */
        if (!foreground)
                return 1;

        /* foreground, let's use the revoked state */
        return *revoked;
}

SEC("fmod_ret/hidraw_is_revoked")
int BPF_PROG(hidraw_bpf_revoked, struct hidraw_list *list)
{
        return is_revoked(list);
}

char LICENSE[] SEC("license") = "GPL";
