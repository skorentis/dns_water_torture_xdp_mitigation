#!/usr/bin/python3

from bcc import BPF
import time
import sys
import json
import ctypes

def usage():
    print("Usage: {0} <if> <section>\n".format(sys.argv[0]))
    print("       {0} <if> -U: unload xdp from interface:<if>\n".format(sys.argv[0]))
    print("       {0} -h: print this message\n".format(sys.argv[0]))
    print("e.g.: {0} eth0 xdp_test\n".format(sys.argv[0]))
    exit(1)

def unload_bpf(b, device):
    print("Removing BPF from XDP hook...")
    b.remove_xdp(device, 0)
    exit(0)

def load_bpf(device, section, mode):
    b = BPF(src_file="xdp_prog_kern.c", cflags=["-w"])
    if "-U" in sys.argv:
        unload_bpf(b, device)
    if ("-h" in sys.argv):
        usage()
        exit(1)
    fn = b.load_func(section, mode)
    b.attach_xdp(device, fn, 0)
    time.sleep(1)
    return b

def transfer_stats_to_bpf(bpf_maps, stats):
    for feature in range(0,7):
        for key in stats[str(feature)]:
            bpf_maps[feature][ctypes.c_uint32(int(key))] = ctypes.c_uint64(stats[str(feature)][key])

if __name__ == "__main__":

    device = sys.argv[1] if len(sys.argv) > 1 else "lo"
    section = sys.argv[2] if len(sys.argv) > 2 else "xdp_test"
    b = load_bpf(device, section, BPF.XDP)

    invalid_stats = json.loads(open("invalid_stats.json", "r").read())
    valid_stats = json.loads(open("valid_stats.json", "r").read())

    ## fill bpf maps with valid-invalid stats
    bpf_valid_maps = []
    bpf_invalid_maps = []

    for i in range(1,8):
        bpf_valid_maps.append(b["valid_feature"+str(i)])
        bpf_invalid_maps.append(b["invalid_feature"+str(i)])
    
    transfer_stats_to_bpf(bpf_valid_maps, valid_stats)
    transfer_stats_to_bpf(bpf_invalid_maps, invalid_stats)

    # ## digits array
    bpf_digits = b["digits"]
    dlist = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39]
    for i in dlist:
        bpf_digits[ctypes.c_uint8(i)] = ctypes.c_uint8(0)

    # ## vowels array 
    bpf_vowels = b["vowels"]
    vlist = [0x41, 0x45, 0x49, 0x4f, 0x55, 0x61, 0x65, 0x69, 0x6f, 0x75]
    for i in vlist:
        bpf_vowels[ctypes.c_uint8(i)] = ctypes.c_uint8(0)

    ## consonants array 
    bpf_consonants = b["consonants"]
    clist = [0x62, 0x63, 0x64, 0x66, 0x67, 0x68, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x70, 0x71, 0x72, 0x73, 0x74, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x42, 0x43, 0x44, 0x46, 0x47, 0x48, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x50, 0x51, 0x52, 0x53, 0x54, 0x56, 0x57, 0x58, 0x59, 0x5a]
    for i in clist:
        bpf_consonants[ctypes.c_uint8(i)] = ctypes.c_uint8(0)

    print("section: " + str(section) + " loaded.\n")