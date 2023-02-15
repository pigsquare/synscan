from scapy.all import *
from threading import Thread
from tqdm import tqdm
from optparse import OptionParser
import itertools
import json
from utils import *


scan_res = []
open_ports = []
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
        print('error:', e)
        return 'error: '+str(e)


def add_res(ip: str, port: int, timeout=1.0, retries=1) -> None:
    result = {
        'ip': ip,
        'port': port,
        'result': scan(ip, port, timeout, retries)
    }
    scan_res.append(result)
    if result['result'] == 'open':
        open_ports.append(result)


def main():
    parser = OptionParser("Usage program -i <target host> -p <target port> -t <time out> -r <retry times>")
    parser.add_option("-i", '--host', type="string",dest="optIP",help="specify target host or website, can include hyphen and comma, or a file path")
    parser.add_option("-p","--port", type="string",dest="optPorts",help="specify target port separated by comma, can include hyphen, or a file path")
    parser.add_option("-t","--timeout", type="float",dest="optTimeout",help="specify time out in seconds", default=0.50)
    parser.add_option("-r","--retry", type="int",dest="optRetry",help="specify retry times", default=1)
    parser.add_option("-o","--output", type="string",dest="optOutput",help="specify the dir to save results", default='./')
    options,args = parser.parse_args()
    # print(options)
    if options.optIP is None or options.optPorts is None:
        print(parser.usage)
        exit(0)
    if os.path.exists(options.optIP):
        with open(options.optIP, 'r') as file:
            ips=parse_ip_range(file.read())
    else:
        ips=parse_ip_range(options.optIP)
    if os.path.exists(options.optPorts):
        with open(options.optPorts, 'r') as file:
            ports=parse_port_range(file.read())
    else:
        ports=parse_port_range(options.optPorts)

    timeout=options.optTimeout
    retry=options.optRetry
    directory = options.optOutput
    for ip, port in tqdm(itertools.product(ips,ports),total=len(ips)*len(ports)):
        t = Thread(target=add_res, args=(ip,port, timeout, retry))
        threads.append(t)
        t.start()
    for thread in threads:
        thread.join()
    scan_res.sort(key=lambda x: (x['ip'], x['port']))
    open_ports.sort(key=lambda x: (x['ip'], x['port']))
    with open(os.path.join(directory, "all_results.json"), 'w')as f:
        json.dump(scan_res,f,indent=2)
    with open(os.path.join(directory, "open_results.json"), 'w')as f:
        json.dump(open_ports,f,indent=2)

if __name__ == '__main__':
    main()
