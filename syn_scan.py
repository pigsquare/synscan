from scapy.all import *
def scan(ip:str,port:int,timeout=1.0)->str:
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")  # 构造标志位为syn的数据包
        result = sr1(packet,timeout=timeout, verbose=0)
        if result is None:
            # print(port,'timeout')
            return "timeout"
        # ls(packet)
        # ls(result)
        if int(result[TCP].flags) == 18:
            # 通过判断响应的数据包中，是否存在第二次握手Ack+syn标志位，存在即端口开放
            # print(ip, "TCP" , port, "open")
            return "open"
            # 注意这里如果使用+号进行字符串拼接的话会导致报错，使用逗号即可拼接
        elif int(result[TCP].flags)==20:
            # print('closed'+str(result[TCP].flags))
            return 'closed'
        else:
            return "received flags: "+str(result[TCP].flags)

    except Exception as e:
        print('except:',e)
        return 'except: '+str(e) 

if __name__ == '__main__':
    scan('39.156.66.10', 80)
    scan("baidu.com", 80)
    for i in range(1024):
        scan('baidu.com', i, 0.5)
    # https://www.codenong.com/cs105593329/