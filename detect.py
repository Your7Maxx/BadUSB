#! /bin/python3

import json
from bcc import BPF

class HidMonitor:
    def __init__(self):
        self.bpf_hid_register = BPF(src_file="hid_register.c")
        self.bpf_hid_register.attach_kprobe(event="hid_register_report", fn_name="sechnic")
        self.bpf_hid_register["events"].open_perf_buffer(self.print_event)

        self.bpf_file_open = BPF(src_file="file_open.c")

    def print_event(self, cpu, data, size):
        event = self.bpf_hid_register["events"].event(data)
        print("Vendor:{}, Product:{}\n".format(event.vendor, event.product))

    def is_white(self, t_vendor, t_product):
        with open('rule.json', 'r') as file:
            json_data = file.read()
            data = json.loads(json_data)

            vendor = data.get('vendor')
            product = data.get('product')

            return 1 if vendor == t_vendor and product == t_product else 0

    def monitor_hid_devices(self):
        path_table = self.bpf_hid_register.get_table("path_table")
        vp_table = self.bpf_hid_register.get_table("vp_table")

        while True:
            try:
                for k, v in vp_table.items():
                    v = vp_table[k]
                    path = hex(v.vendor)[2:] + ':' + hex(v.product)[2:]
                    path_len = len(path)

                    if not self.is_white(v.vendor, v.product):
                        flag = 1
                    else:
                        flag = 0

                    for k, v in path_table.items():
                        v = path_table[k]
                        v.pathname = path.encode()
                        v.path_len = path_len
                        v.flag = flag
                        path_table[k] = v

                    self.bpf_file_open.trace_print()

            except KeyboardInterrupt:
                exit()

if __name__ == "__main__":
    hidmonitor = HidMonitor()
    hidmonitor.monitor_hid_devices()