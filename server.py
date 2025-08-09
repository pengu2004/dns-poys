import os
import fcntl
import struct
import socket

# BPF constants from <net/bpf.h>
BIOCSETIF      = 0x8020426c
BIOCIMMEDIATE  = 0x80044270
BIOCGBLEN      = 0x40044266

# BPF header format (time_sec, time_usec, caplen, datalen, hdrlen)
BPF_HDR_FMT = "IIIIH"  # timeval_sec, timeval_usec, caplen, datalen, hdrlen
BPF_HDR_LEN = struct.calcsize(BPF_HDR_FMT)

def open_bpf(interface):
    # Find an available /dev/bpf device
    for i in range(255):
        print(i)
        dev = f"/dev/bpf{i}"
        try:
            bpf_fd = os.open(dev, os.O_RDWR)
            break
        except FileNotFoundError:
            raise
        except OSError:
            continue
    else:
        raise RuntimeError("No /dev/bpf devices available")

    # Bind to the interface

    ifreq = struct.pack('16sH14s', interface.encode(), socket.AF_INET6, b'\x00'*14) #socket.AF_INET is an integer representing ipv4 addressing
    fcntl.ioctl(bpf_fd, BIOCSETIF, ifreq)

    # Set immediate mode so reads return as soon as a packet arrives

    fcntl.ioctl(bpf_fd, BIOCIMMEDIATE, struct.pack('I', 1))

    # Get buffer length
    buf_len_bytes = fcntl.ioctl(bpf_fd, BIOCGBLEN, struct.pack('I', 0))
    buf_len = struct.unpack('I', buf_len_bytes)[0]

    return bpf_fd, buf_len

def parse_ethernet(pkt):
    if len(pkt) < 14:
        return None, None
    dst, src, eth_type = struct.unpack('!6s6sH', pkt[:14])
    return eth_type, pkt[14:]

def parse_ip(pkt):
    if len(pkt) < 20:
        return None, None, None, None
    version_ihl = pkt[0]
    ihl = (version_ihl & 0x0F) * 4 # how many to skip before reaching payload
    proto = pkt[9]
    src_ip = socket.inet_ntoa(pkt[12:16])
    dst_ip = socket.inet_ntoa(pkt[16:20])
    return proto, src_ip, dst_ip, pkt[ihl:]

def parse_udp(pkt):
    if len(pkt) < 8:
        return None, None
    src_port, dst_port, length, checksum = struct.unpack('!HHHH', pkt[:8])
    return src_port, dst_port

def count_dns_queries(interface):
    bpf_fd, buf_len = open_bpf(interface)
    dns_count = 0
    print(f"Listening on {interface} for UDP/53 traffic...")

    while True:
        data = os.read(bpf_fd, buf_len)
        offset = 0
        while offset < len(data):
            # Read BPF header
            sec, usec, caplen, datalen, hdrlen = struct.unpack(
                BPF_HDR_FMT, data[offset:offset+BPF_HDR_LEN]
            )
            pkt_start = offset + hdrlen
            pkt_end = pkt_start + caplen
            pkt = data[pkt_start:pkt_end]

            # Parse Ethernet
            eth_type, payload = parse_ethernet(pkt)
            if eth_type != 0x0800:  # Not IPv4
                offset += ((hdrlen + caplen + 3) & ~3)
                continue

            # Parse IP
            proto, src_ip, dst_ip, udp_segment = parse_ip(payload)
            if proto != 17:  # Not UDP
                offset += ((hdrlen + caplen + 3) & ~3)
                continue

            # Parse UDP
            src_port, dst_port = parse_udp(udp_segment)
            if src_port == 53 or dst_port == 53:
                dns_count += 1
                print(f"DNS query #{dns_count} {src_ip} -> {dst_ip}")

            # Move to next packet (4-byte aligned)
            offset += ((hdrlen + caplen + 3) & ~3)

if __name__ == "__main__":
    count_dns_queries("en0")  # Change to your active interface