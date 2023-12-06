#include <linux/usb.h>
#include <linux/hid.h>
#include <linux/device.h>


struct data_t {
    u32 vendor;
    u32 product;
};

struct path_t{
    char pathname[100];
    int path_len;
    int flag;
};

BPF_TABLE_PUBLIC("hash", u32, struct data_t, vp_table, 1);
BPF_TABLE_PUBLIC("hash", u32, struct path_t, path_table, 1);

BPF_PERF_OUTPUT(events);

int sechnic(struct pt_regs *ctx,struct hid_device *hid, struct hid_field *field, struct hid_usage *usage) {
    struct data_t data = {};
    struct path_t path = {};

    u32 vendor = hid->vendor;
    u32 product = hid->product;

    data.vendor = vendor;
    data.product = product;

    u32 id = 1;

    struct path_t *path_tmp = path_table.lookup(&id);

    if(path_tmp) {
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }else{
        char p[] = "maxx";
        bpf_probe_read_str(&path.pathname, sizeof(path.pathname), p);
        path_table.update(&id, &path);
    }

    struct data_t *data_tmp = vp_table.lookup(&id);

    if(data_tmp) {
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
    }else{
       vp_table.update(&id, &data);
    }

    events.perf_submit(ctx, &data,sizeof(data));
    return 0;
}
