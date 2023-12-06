#! /bin/python3

import json
from bcc import BPF

class KeycodeMonitor:

    def __init__(self, src_file='keycode.c', keycode_file='keycode.json', hidtype_file='hidtypes.json'):
        self.b = BPF(src_file=src_file)
        self.b.attach_kprobe(event="hidinput_hid_event", fn_name="sechnic")
        self.b["events"].open_perf_buffer(self.print_event)

        with open(keycode_file, 'r') as file1:
            self.keycode = json.load(file1)

        with open(hidtype_file, 'r') as file2:
            self.hidtypes = json.load(file2)

    def print_event(self, cpu, data, size):
        try:
            event = self.b["events"].event(data)
            code = self.keycode.get(str(event.code), 'Unknown')
            hidtype = self.hidtypes.get(str(event.type), 'Unknown')
            print("[*] Vendor:%d, Product:%d, Type:%s, Code:%s" % (event.vendor, event.product, hidtype, code))
        except :
            pass

    def start_monitoring(self):
        print("[*] start monitoring keycode input.")
        print("--" * 20)
        while True:
            try:
                self.b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

if __name__ == "__main__":
    keycodeMonitor = KeycodeMonitor()
    keycodeMonitor.start_monitoring()
