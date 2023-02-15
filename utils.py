import socket
import struct
import itertools


def parse_ip_range(ip_range):
    """Parses a string of IPs separated by commas and/or hyphens and returns a list of individual IP addresses"""
    ips = []

    # Split the string into IP ranges
    ip_ranges = ip_range.replace(' ', '').replace('\n', ',').split(',')

    # Loop over the IP ranges
    for ip_range in ip_ranges:
        if not ip_range:
            continue
        # Check for a hyphen
        if '-' in ip_range:
            try:
                # Split the range into start and end IPs
                start_ip, end_ip = ip_range.split('-')
                # Convert the start and end IPs to integers
                start_ip = struct.unpack("!I", socket.inet_aton(start_ip))[0]
                end_ip = struct.unpack("!I", socket.inet_aton(end_ip))[0]
                # Loop over the IP range and append each IP to the list
                for ip in range(start_ip, end_ip+1):
                    ips.append(socket.inet_ntoa(struct.pack("!I", ip)))
            except Exception as e:
                ips.append(ip_range)
        else:
            # Append the single IP to the list
            ips.append(ip_range)

    return ips


def parse_port_range(port_range):
    """Parses a string of ports separated by commas and/or hyphens and returns a list of individual ports"""
    ports = []
    port_ranges = port_range.replace(' ', '').replace('\n', ',').split(',')

    for port_range in port_ranges:
        if not port_range:
            continue
        try:
            # Check for a hyphen
            if '-' in port_range:
                # Split the range into start and end ports
                start_port, end_port = port_range.split('-')
                start_port = int(start_port)
                end_port = int(end_port)
                # Loop over the port range and append each port to the list
                for port in range(start_port, end_port+1):
                    ports.append(port)
            else:
                # Append the single port to the list
                ports.append(int(port_range))
        except Exception as e:
            pass
    return ports


if __name__ == "__main__":
    print(parse_ip_range("baidu.com"))
    print(parse_port_range("1,2,3,8,80-99,8880"))
    for ip, port in itertools.product(parse_ip_range("192.168.0.100-192.168.0.102,baidu.com"), parse_port_range("20-30,80,443-445")):
        print(ip, port)
