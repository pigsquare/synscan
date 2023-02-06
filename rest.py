from scapy.all import *
def scan(ip,port):
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")  # 构造标志位为syn的数据包
        result = sr1(packet,timeout=0.5, verbose=0)
        if int(result[TCP].flags) == 18:
            # 通过判断响应的数据包中，是否存在第二次握手Ack+syn标志位，存在即端口开放
            time.sleep(0.1)
            print(ip, "TCP" , port, "open")
            # 注意这里如果使用+号进行字符串拼接的话会导致报错，使用逗号即可拼接
        else:
            print('closed')
        return

    except Exception as e:
        print('except',e)
        pass

if __name__ == '__main__':
    scan('39.156.66.10', 80)
    # https://www.codenong.com/cs105593329/