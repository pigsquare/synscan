import random
import socket
import struct

# Generate 1000 random IPv4 addresses
ips = []
for _ in range(1000):
    ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    ips.append(ip)

# Write IP addresses to file
with open('ip.txt', 'w') as f:
    f.write('\n'.join(ips))
