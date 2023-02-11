from scapy.all import *
def scan(ip:str,port:int,timeout=1.0)->str:
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")  # 构造标志位为syn的数据包
        result = sr1(packet,timeout=timeout, verbose=0) # sr1函数获取到结果数据包
        if result is None:
            # 如果超时没有收到回复，有可能是服务器地址有误或者包被丢弃
            # print(port,'timeout')
            return "timeout"
        # ls(packet)
        # ls(result)
        if int(result[TCP].flags) == 18:
            # 通过判断响应的数据包中，是否存在第二次握手Ack+syn标志位（对应int为20），存在即端口开放
            # print(ip, "TCP" , port, "open")
            return "open"
            # 注意这里如果使用+号进行字符串拼接的话会导致报错，使用逗号即可拼接
        elif str(result[TCP].flags).find("R")!=-1:
            # 如果存在reset，说明端口关闭
            # print('closed'+str(result[TCP].flags))
            return 'closed'
        else:
            return "received flags: "+str(result[TCP].flags)

    except Exception as e:
        print('except:',e)
        return 'except: '+str(e) 

if __name__ == '__main__':
    scan('39.156.66.10', 80)
    scan("baidu.com", 443)
    for i in (21,25,80,443,8080,8888,53):
        print(scan('sq.sjnb.club', i, 0.5))
    # https://www.codenong.com/cs105593329/gvh12hhju9