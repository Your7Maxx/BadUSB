#! /bin/python3

import json
from bcc import BPF

dict = {}

class KeycodeMonitor:

    def __init__(self, src_file='keycode.c', keycode_file='keycode.json', hidtype_file='hidtypes.json'):
        self.b = BPF(src_file=src_file)
        self.b.attach_kprobe(event="hidinput_hid_event", fn_name="sechnic")
        self.b["events"].open_perf_buffer(self.print_event)

        with open(keycode_file, 'r') as file1:
            self.keycode = json.load(file1)

        with open(hidtype_file, 'r') as file2:
            self.hidtypes = json.load(file2)
        self.key_output_status = {}

    def print_event(self, cpu, data, size):
        try:
            event = self.b["events"].event(data)
            code = self.keycode.get(str(event.code), 'Unknown')
            hidtype = self.hidtypes.get(str(event.type), 'Unknown')
            key_identifier = (event.type, event.code, event.value)

            if event.code not in [29, 42, 56, 125, 97, 54, 100, 126]:
                if self.key_output_status.get(key_identifier, False):
                    self.key_output_status.clear()
                    return

                else:
                    print("[*] Vendor:%d, Product:%d, Type:%d, Code:%s" % (event.vendor, event.product, event.type, code))
                    self.key_output_status[key_identifier] = True


        except Exception as e:
            print(f"Error processing event: {e}")

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
