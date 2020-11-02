# This is a sample Python script.
import sys
import getopt
import _thread
import time
from random import randint
from subprocess import Popen, PIPE
import socket
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr, srp1, sr1
import IPy
import re

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


'''
功能：IP处理，将用户命令输入的IP进行匹配和处理
输入：目标IP或子网IP
输出：全部子网ip或精确目标ip
     iplist：列表形式输出
'''
def IPcont(ip):
    iplist = []
    for x in IPy.IP(ip):
        iplist.append(x)
    return iplist

'''
正则表达式匹配IP地址
当末尾为0时并填充子网ip
'''
def IPcont2(ip):
    iplist = []
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                ip):
        print("IP vaild")
        ip = ip.split(".")

        if int(ip[3]) == 0:
            for ip[3] in range(1, 254):
                iplist.append(str(ip[0]+"."+ip[1]+"."+ip[2]+"."+str(ip[3])))
            print(iplist)

    else:
        print("IP invaild")
        if re.match(r"^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$", ip, re.I):
            print("IPv6 vaild")
        else:
            print("IPv6 invaild")



'''
ping扫描
功能:探测子网内主机活性
输入参数: 
     ip地址
输出：
     打印是否存在

'''
def Ping_S(ip):
    '''
    ipaddr = IPcont(ip)
    for i in ipaddr:
    '''
    #ping命令的执行
    check = Popen("ping {0} \n".format(ip), stdin=PIPE, stdout=PIPE, shell=True)
    #读取返回信息
    data = check.stdout.read()
    data = data.decode("gbk")
    print("域名IP地址为:"+socket.gethostbyname(ip))
    if 'TTL' in data:
        sys.stdout.write('%s is live' % ip)

'''
TCP端口连接
功能:与输入IP或网站进行TCP链接完成三次握手
输入参数：
     ip:目标IP 
     port:目标端口
输出参数：
     打印端口是否存在
     
'''
def TCP_Scan(ip, port):
    print("当前：" + ip)
    port = int(port)
    ip = str(ip)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        result = s.connect_ex((ip, port))
        '''s.send('Only see you\n')
        banner = s.recv(1024)'''
        if result == 0:
            print('端口开发:%d' % port)
        else:
            print('端口关闭:%d' % port)
        s.close()
    except socket.error as e:
        print("!发生错误：", e)

'''
TCP扫描
功能:全扫描完成三次握手从而获得信息
     多线程
输入参数：ip:目标参数 
         i:识别目标参数类型       
'''
def Tcp_S(ip, i):
    if i != 'ip':
        try:
            ip = socket.gethostbyname(ip)
        except socket.error as e:
            print("未能解析出地址:", e)
            return
    ports = input("请输入你想测试的端口号\n(','隔开,all即为全部探测):")
    ports = ports.split(",")
    if ports[0] == 'all':
        for port in range(1, 65535):
            #_thread.start_new_thread(Ping_S, (a,))
            #time.sleep(0.1)
            #多线程调用TCO_Scan扫描
            _thread.start_new_thread(TCP_Scan, (ip, port,))
            time.sleep(0.1)
            #ConScan(ip, int(port))
    else:
        for port in ports:
            TCP_Scan(ip, int(port))

'''
SYN端口连接
功能:与输入IP或网站进行完成半次三次握手
输入参数：
     ip:目标IP 
     port:目标端口
输出参数：
     打印端口是否存在
'''
def Syn_scan(ip, port):
    #print(ip,port)
    temp = sr(IP(dst=ip) /
              TCP(dport=(int(port), int(port)), flags='S'), timeout=3, verbose=False)
    result = temp[0].res
    #print(result)
    for i in range(len(result)):
        if result[i][1].haslayer(TCP):
            #取出返回包的标志位
            tcp_pack = result[i][1].getlayer(TCP).fields
            #print(tcp_pack)
            #标准位返回flags=18既为ACK+SYN包
            if tcp_pack['flags'] == 18:#2^4+2
                print(ip+" "+str(tcp_pack['sport'])+"端口"+'开放')
                return
    print(ip+" "+str(port)+"端口"+'关闭')

'''
功能：SYN扫描：CP半扫描，只完成一半的三次握手接受到目标发送SYN和ACK包终止
输入参数：
    发送者IP
    目标IP
'''
def Syn_S(ip, i):
    if i != 'ip':
        try:
            ip = socket.gethostbyname(ip)
        except socket.error as e:
            print("未能解析出地址:", e)
            return
    ports = input("请输入你想测试的端口号\n(','隔开,all即为全部探测):")
    ports = ports.split(",")
    if ports[0] == 'all':
        for port in range(1, 65535):
            # _thread.start_new_thread(Ping_S, (a,))
            # time.sleep(0.1)
            _thread.start_new_thread(Syn_scan, (ip, port,))
            time.sleep(0.1)
            # ConScan(ip, int(port))
    else:
        for port in ports:
            Syn_scan(ip, int(port))
    #print(ip)

'''
获取本地IP子网段
'''
def get_local():
    hostname = socket.gethostname()
    localip = socket.gethostbyname(hostname)
    localipnums = localip.split('.')
    localipnums.pop()
    localipnet = '.'.join(localipnums)
    return localipnet

'''
获取时间用作时间对比
'''
def get_time():
    year = time.strftime('%Y-%m-%d', time.localtime())
    minute =time.strftime('%H-%M-%S', time.localtime())
    return year+minute

'''
ARP扫描
功能：扫描本地IPc段的ip与物理地址
'''
def arp_scan():
    localnet = get_local()
    result = []
    for ipfix in range(1, 254):
        ip = localnet + "."+str(ipfix)
        #构造ARP包
        arppkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
        #发送并接受返回包
        res = srp1(arppkt, timeout=1, verbose=0)
        #print(res)
        if res:
            result.append(res.psrc)
            print("IP:"+res.psrc+"MAC:"+res.hwsrc)
        else:
            print("IP:"+ip+"!ARP扫描失败!")

'''
真实的udp扫描
'''
def udp_scan(ip, port):
    print(ip,port)
    try:
        packet = IP(dst=ip)/UDP(dorp=port, sport=randint(1, 65535))
        result = sr1(packet, timeout=5, verbose=0)
        time.sleep(0.1)
        if result is None:
            print("IP"+ip+":"+str(port)+"is open")
    except:
        print("!扫描失败!")
    print()

'''
调用Udp批量扫描

'''
def udp_s(ip):
    ports = input("请输入你想测试的端口号\n(','隔开,all即为全部探测):")
    ports = ports.split(",")
    if ports[0] == 'all':
        for port in range(1, 65535):
            # _thread.start_new_thread(Ping_S, (a,))
            # time.sleep(0.1)
            _thread.start_new_thread(udp_scan, (ip, port,))
            time.sleep(0.1)
            # ConScan(ip, int(port))
    else:
        for port in ports:
            udp_scan(ip, int(port))
    #print()

'''
参数处理函数
功能：采用长短命令获取用户参数,捕捉用户命令输入从而传参
参数：argv  用户输入参数
'''
def main(argv):
    #print(argv)
    port = 0
    ip = ''
    try:
        #长短命令的参数捕捉
        opts, args = getopt.getopt(argv, 'hpsuti:a:', ['help', 'ip=', 'post=', 'arp'])
    except getopt.GetoptError:
        print('main,py -s/t/p 端口号 --ip ip地址')
        sys.exit()
    #print(opts)
    for opt, arg in opts:
        # 调用帮助文档
        if opt in ('-h', '--help'):
            print("标准样式main.py -p -i 127.0.0.1")
            print("扫描方式：")
            print("-p ping扫描：探测主机活性和网站活性,以及子网内主机存在状态")
            print("-t TCP全扫描：扫描网站或ip的端口号(不带参数调用后续提示输入)")
            print("-s SYN扫描：扫描网站或ip的端口号(不带参数调用后续提示输入)")
            print("-u UDP扫描")
            print("--arp ARP扫描：或者本地IP C段的IP与物理地址，不用跟-i -a")
            print("用户目标选定：")
            print("-i 输入形式为目标IP地址")
            print("-a 输入形式为目标网址")
            sys.exit()

        if opt == '-s':
            print("-----开始进行SYN扫描-----")
            for i in range(len(opts)):
                '''if opts[i][0] == '-p':
                    port = opts[i][1]'''
                if opts[i][0] == '-i' or opts[i][0] == '--ip':
                    ip = opts[i][1]
                    a = 'ip'
                    Syn_S(ip, a)
                    sys.exit()
                if opts[i][0] == '-a':
                    address = opts[i][1]
                    a = 'address'
                    Syn_S(address, a)
                    sys.exit()
            #print(args)

        if opt == '-t':
            print("-----开始进行TCP扫描-----")
            for i in range(len(opts)):
                '''if opts[i][0] == '-p':
                    port = opts[i][1]'''
                if opts[i][0] == '-i' or opts[i][0] == '--ip':
                    ip = opts[i][1]
                    a = 'ip'
                    Tcp_S(ip, a)
                    sys.exit()
                if opts[i][0] == '-a':
                    address = opts[i][1]
                    a = 'address'
                    Tcp_S(address, a)
                    sys.exit()


        if opt == '-p':
            print("-----开始进行ping扫描探测活性主机/网址取IP-----")
            for i in range(len(opts)):
                if opts[i][0] == '-i' or opts[i][0] == '--ip':
                    ip = opts[i][1]
                    ipaddr = IPcont(ip)
                    if len(ipaddr) > 1:
                        for a in ipaddr:
                            #多线程调用Ping_S函数
                            _thread.start_new_thread(Ping_S, (a,))
                            time.sleep(0.1)

                    else:
                        Ping_S(ip)

                    sys.exit()

                if opts[i][0] == '-a':
                    address = opts[i][1]
                    Ping_S(address)
                    sys.exit()

        if opt == '--arp':
            print("-------------------ARP局域网扫描-----------------")
            arp_scan()
            sys.exit()

        if opt == '-u':
            print("-------------------UDP主机端口扫描------------------")
            for i in range(len(opts)):
                if opts[i][0] == '-i' or opts[i][0] == '--ip':
                    ip = opts[i][1]
                    udp_s(ip)
                    sys.exit()
            sys.exit()



# Press the green button in the gutter to run the script.

if __name__ == '__main__':
    main(sys.argv[1:])

    #IPcont2("127.0.0.0")

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
