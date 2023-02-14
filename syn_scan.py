from scapy.all import *
from threading import Thread
from tqdm import tqdm


res = []
threads = []


def scan(ip: str, port: int, timeout=1.0, retries=1) -> str:
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")  # 构造标志位为syn的数据包
        for i in range(retries):  # 重试机制
            result = sr1(packet, timeout=timeout, verbose=0)  # sr1函数获取到结果数据包
            if result:  # 如果收到回复，跳出重试
                break
        if result is None:
            # 如果超时没有收到回复，有可能是服务器地址有误或者包被丢弃
            # print(port,'timeout')
            return "timeout"
        # ls(packet)
        # ls(result)
        if int(result[TCP].flags) == 18:
            # 通过判断响应的数据包中，是否存在第二次握手Ack+syn标志位（A=16, S=2, 对应int为18），存在即端口开放
            # print(port, "open")
            return "open"
        elif str(result[TCP].flags).find("R") != -1:
            # 如果存在reset(R)，说明端口关闭
            # print('closed '+str(result[TCP].flags))
            return "closed"
        else:  # 一般不会收到除reset或者syn+ack的回复，兜底规则
            return "received flags: "+str(result[TCP].flags)

    except Exception as e:
        print('except:', e)
        return 'except: '+str(e)


def add_res(ip: str, port: int, timeout=1.0, retries=1) -> None:
    res.append({
        'ip': ip,
        'port': port,
        'result': scan(ip, port, timeout, retries)
    })
    pass


if __name__ == '__main__':
    # scan('39.156.66.10', 80)
    # scan("baidu.com", 443)
    s_t = time.time()
    for i in tqdm(range(10535)):
        t = Thread(target=add_res, args=('sq.sjnb.club', i, 2, 2))
        threads.append(t)
        t.start()
        # res = scan('sq.sjnb.club', i, 2, 3)
        # if res != 'closed':
        #     print(i, res)
    for thread in tqdm(threads):
        thread.join()
    # res.sort()
    for r in res:
        if (r['result'] != 'closed'):
            print(r)
    e_t = time.time()
    print(e_t-s_t)
    # https://www.codenong.com/cs105593329/gvh12hhju9
