#include <linux/usb.h>
#include <linux/hid.h>

struct data_t {
//	u32 pid;
        u32 vendor;
        u32 product;
        u32 type;
        u32 code;

};

BPF_PERF_OUTPUT(events);

int sechnic(struct pt_regs *ctx,struct hid_device *hid, struct hid_field *field, struct hid_usage *usage){

    struct data_t data = {};

    data.vendor = hid->vendor;
    data.product = hid->product;
    data.type = hid->type;
    data.code = usage->code;
  //  data.pid = bpf_get_current_pid_tgid();

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

