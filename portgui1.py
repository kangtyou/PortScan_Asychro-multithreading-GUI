import ipaddress   # 把ip数字转换为ip格式
import ast         # 计算string
import PySimpleGUI as sg # GUI界面
import socket         # 建立网络连接
import threading       #多线程
from queue import Queue
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
from netaddr import *
import time
from tkinter import filedialog

from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
import smtplib

#GUI界面
poolip = []

result = []

result_lock = threading.Lock()

print_lock = threading.Lock()

q = Queue()

class thread_with_trace(threading.Thread):
  def __init__(self, *args, **keywords):
    threading.Thread.__init__(self, *args, **keywords)
    self.killed = False
  
  def start(self):
    self.__run_backup = self.run
    self.run = self.__run      
    threading.Thread.start(self)
  
  def __run(self):
    sys.settrace(self.globaltrace)
    self.__run_backup()
    self.run = self.__run_backup
  
  def globaltrace(self, frame, event, arg):
    if event == 'call':
      return self.localtrace
    else:
      return None
  
  def localtrace(self, frame, event, arg):
    if self.killed:
      if event == 'line':
        raise SystemExit()
    return self.localtrace
  
  def kill(self):
    self.killed = True
#发送线程任务定义
def sendingthreader(lockdate,start_time,amount,cost_time,threadwork):
    
    while True:
        
        
        worker = q.get()
        host = f"{ipaddress.IPv4Address(worker[0])}"
        send(IP(dst=host) / TCP(dport=worker[1], flags='S'), verbose=False)
        time.sleep(worker[2])
        #doScan(worker[0],worker[1],timeout=worker[2])
        print_lock.acquire()
        print("sending to {}:{}".format(host,worker[1]))
        print_lock.release()
        q.task_done()
        progress = (q.qsize()/amount) * 1000
        lockdate.window.write_event_value('-Progress-', progress)
        if q.empty():
            end_time = time.time()
            time_cost = end_time - start_time
            time_cost = time_cost + cost_time
            lockdate.window.write_event_value('-Done-', time_cost)
            for work in threadwork:
                work.kill()
                work.join()
            


#收包定义
def receivethreader(lockdata):
    while True:
        
        
        print ("嗅探中:")
        def prn(pkt):                         #对过滤器过滤出的数据包进行处理
            #lockdata.current += 1
            #lockdata.progress = lockdata.progress_max * (lockdata.current / lockdata.totalamout)
            #lockdata.window['scan_progress'].update_bar(lockdata.progress)
            host = pkt.sprintf("%IP.src%")
            port = pkt.sprintf("%IP.sport%")
            if host not in poolip:
                return
            for i in result:
                if host == i[0] and port == i[1]:
                    return 
            result_lock.acquire()
            result.append([f"{host}", f"{port}"])
            #lockdata.window['results_table'].update(lockdata.results)
            result_lock.release()
            lockdata.window.write_event_value('-Update-', result)
            #print('port is open', port)
                #由于发包模块将seq定位0x11111111，返回的包ack值应该+1
            print_lock.acquire()
            print (pkt.sprintf("the port is opening %IP.src%:%IP.sport%  %TCP.flags%"))
            print_lock.release()
            
                                            #输出ip：port flags
        iface = 'Intel(R) Dual Band Wireless-AC 8265'
        userIP = '10.151.117.226'
        sniff(iface = iface , filter = 'tcp and dst %s and tcp[13:1] & 18==18'%userIP , prn = prn)

        
MY_SENDER = '1573049371@qq.com'  # 发件人邮箱账号
MY_ADMIN = '1573049371@qq.com'
MY_PASS = 'xxxxxxxxxxxxxxx'
class Mail:
    def __init__(self):
        # 登录邮箱
      
        self.server = smtplib.SMTP_SSL("smtp.qq.com", 465)  # 用发件人邮箱的SMTP服务器地址和端口创建一个新的连接实例
        self.server.login(MY_SENDER, MY_PASS)  # 登录
    
    def mail(self, my_user, title, body):
        # 发邮件
         
        try:
            self.loopconect()
            self.msg = MIMEMultipart()
            self.msg['To'] = formataddr(["Automessage", my_user])
            self.msg['From'] = formataddr(["PortScan", MY_SENDER])
            self.msg['Subject'] = Header(title, 'utf-8').encode()
            
            # 文本
            msg_text = MIMEText(body, 'plain', 'utf-8')
            msg_text["Accept-Language"] = "zh-CN"
            msg_text["Accept-Charset"] = "ISO-8859-1,utf-8"
            self.msg.attach(msg_text)
            
            # 截图
            
            # 括号中对应的是发件人邮箱账号、收件人邮箱账号、发送邮件
            self.server.sendmail(MY_SENDER, [my_user, ], self.msg.as_string())
            print('[+]已经向{}发送邮箱'.format(my_user))
        except Exception as e:
            print("[-]邮箱发送失败")
            print("[-]" + self.msg.as_string())
    
    def quit(self):
        self.server.quit()
        print('[+] 已经正常退出邮箱')


    def test_conn_open(self):
        try:
            status = self.server.noop()[0]
        except:
            status = -1
        return True if status == 250 else False

    def loopconect(self):
        if not self.test_conn_open():
            self.server = smtplib.SMTP_SSL("smtp.qq.com.net", 465)                         
            self.server.login(MY_SENDER, MY_PASS)
    
       

def main():
    class datalock():
        def __init__(self):
            sg.change_look_and_feel('Material2')
        
            group_ip = [
                [
                    sg.Text('起始IP:', size=(10, 1), auto_size_text=False,
                            justification='right'),
                    sg.InputText(key="start_ip", default_text="baidu.com")
                ],
                [
                    sg.Text('终止IP:', size=(10, 1), auto_size_text=False,
                            justification='right'),
                    sg.InputText(key="end_ip", default_text="baidu.com")
                ]
            ]
            group_port = [
                [
                    sg.Text('起始端口:', size=(10, 1), auto_size_text=False,
                            justification='right'),
                    sg.Input(key="start_port", default_text="1")
                ],
                [
                    sg.Text('目的端口:', size=(10, 1), auto_size_text=False,
                            justification='right'),
                    sg.Input(key="end_port", default_text="65535")
                ],
            ]
            group_timeout = [
                [
                    sg.Text('时间间隔 (s):', size=(10, 1), auto_size_text=False,
                            justification='right'),
                    sg.Input(key="timeout", default_text="0.01")
                ],
            ]
            group_threads = [
                [
                    sg.Text('线程值:', size=(10, 1), auto_size_text=False,
                            justification='right'),
                    sg.Input(key="threads", default_text="1")
                ],
            ]
            group_save_load = [
                [
                    sg.Button('保存'),
                    sg.Button('加载')
                ],
            ]

            group_quit_resume = [
                [
                    sg.Button('停止'),
                    sg.Button('恢复扫描'),
                    sg.Button('清除')
                ],
            ]
            group_scan = [
                [
                    sg.Button('扫描', size=(10, 1))
                ],
            ]

            layout_left = [
                [sg.Text('端口扫描设置')],

                [sg.Column(group_ip)],
                [sg.Column(group_port)],
                [sg.Column(group_timeout)],
                [sg.Column(group_threads)],
                [
                    sg.Column(group_scan),
                    sg.ProgressBar(1000, orientation='h', size=(27, 20),
                                    key='scan_progress',
                                    bar_color=("#003399", "#ffffff"))
                ]
            ]

            layout_right = [
                [sg.Text('扫描结果')],
                [
                    sg.Table(values=[["", ""], ],
                                headings=["IP address", "Port Number"],
                                size=(40, 12),
                                max_col_width=25,
                                key='results_table',
                                num_rows=10, ),
                ],
                [
                    sg.Column(group_save_load),
                    sg.Column(group_quit_resume)
                ]
            ]

            layout_status_bar = [
                [
                    sg.StatusBar('加载...',
                                    size=(90, 1),
                                    auto_size_text=True,
                                    relief='sunken',
                                    key='status_ready')
                ]
            ]

            layout = [
                [
                    sg.Column(layout_left),
                    sg.Column(layout_right)
                ],
                [
                    sg.Column(layout_status_bar)
                ]
            ]
            # 数据锁
            self.lock = threading.Lock()
            self.current = 0
            self.results = []
            self.progress = 0
            self.totalamout = 0
            self.progress_max = 1000
            self.window = sg.Window("端口扫描", layout)
    lockdata = datalock()
    start_time = 0
    worker = []
    amount = 0
    count = 0
    threads = 0
    mail = Mail()
    while True:
        event, values = lockdata.window.read()
        if event in ('停止'):
            for work in worker:
                work.kill()
                work.join()
        elif event in ('清除'):
            lockdata.window['results_table'].update('')
        elif event in ('保存'):
            
            lockdata.window['status_ready'].update("保存数据到文件中...")
            start_host = values['start_ip']
            end_host = values['end_ip']
            port_min = (values['start_port'])
            port_max = (values['end_port'])
            savejson = []
            f = open(start_host + " to " + end_host + " " + port_min + " to " + port_max + '.txt', 'w')
            savejson.append(start_host)
            savejson.append(end_host)
            savejson.append(port_min)
            savejson.append(port_max)
            end_time = time.time()
            time_cost = end_time-start_time
            savejson.append(time_cost)
            savejson.append(len(result))
            savejson.append(result)
            savejson.append(len(worker))
            savejson.append(amount)
            for i in range(0,q.qsize()):
                item = q.get()
                savejson.append(item)
            
            for i in savejson:
                q.put(i)
            f.write(str(savejson))
            f.close()

        elif event in ('加载'):
            lockdata.window['status_ready'].update("从文件中读取数据...")
            file_path = filedialog.askopenfilename()
            f2 = open(file_path, 'r').read()
            line = ast.literal_eval(f2) #将字符串形式的数组转换成数组
            starthost = line[0]
            endhost = line[1]
            startip = line[2]
            endip = line[3]
            start_host_ip = socket.gethostbyname(starthost)
            end_host_ip = socket.gethostbyname(endhost)
            ip_min = ipaddress.IPv4Address(start_host_ip)
            ip_max = ipaddress.IPv4Address(end_host_ip)
            int_ip_min = int(ip_min)
            int_ip_max = int(ip_max)
            for ip in range(int_ip_min, int_ip_max + 1):
                ip_text = f"{ipaddress.IPv4Address(ip)}"
                poolip.append(ip_text)
            lockdata.window['start_ip'].update(starthost)
            lockdata.window['end_ip'].update(endhost)
            lockdata.window['start_port'].update(startip)
            lockdata.window['end_port'].update(endip)
            time_cost = line[4]
            lenth = line[5]
            result.clear()
            for i in line[6]:
                result.append(i)
            lockdata.window['results_table'].update(result)
            q.queue.clear()
            for i in line[9:]:
                q.put(i)
            start_time = time.time()
            threads = line[7]-1
            lockdata.window['threads'].update(threads)
            amount = line[8]
            worker.clear()
            t =  thread_with_trace(target=receivethreader,args=(lockdata,))
            t.daemon = False
            t.start()
            worker.append(t)
            for x in range(threads):
                t = thread_with_trace(target=sendingthreader,args=(lockdata,start_time,amount,time_cost,worker))
                t.daemon = True
                t.start()
                worker.append(t)

            


        elif event in ('扫描'):
            lockdata.results = []
            lockdata.window['status_ready'].update("准备数据中...")
            start_host = values['start_ip']
            end_host = values['end_ip']

            start_host_ip = socket.gethostbyname(start_host)
            end_host_ip = socket.gethostbyname(end_host)
            ip_min = ipaddress.IPv4Address(start_host_ip)
            ip_max = ipaddress.IPv4Address(end_host_ip)
            int_ip_min = int(ip_min)
            int_ip_max = int(ip_max)

            port_min = int(values['start_port'])
            port_max = int(values['end_port'])
            num_ports = port_max - port_min + 1
            num_ips = int_ip_max - int_ip_min + 1

            timeout = float(values['timeout'])

            threads = int(values['threads'])
            
            #设置线程数
            result.clear()
            #lockdata.totalamout = num_ips * num_ports
            #队列任务准备
            for ip in range(int_ip_min, int_ip_max + 1):
                ip_text = f"{ipaddress.IPv4Address(ip)}"
                poolip.append(ip_text)

            for ip in range(int_ip_min, int_ip_max + 1):
                ip_text = f"{ipaddress.IPv4Address(ip)}"
        
                for port in range(port_min, port_max + 1):
                    work = []
                    work.append(ip)
                    work.append(port)
                    work.append(timeout)
                    q.put(work)
            lockdata.window['status_ready'].update("开始扫描...")
            amount = q.qsize()
            t =  thread_with_trace(target=receivethreader,args=(lockdata,))
            t.daemon = False
            t.start()
            worker.append(t)

            
            start_time = time.time()

            for x in range(threads):
                t = thread_with_trace(target=sendingthreader,args=(lockdata,start_time,amount,0,worker))
                t.daemon = True
                t.start()
                worker.append(t)

            

     
        elif event == '-Update-':
            lockdata.window['results_table'].update(values['-Update-'])
        elif event == '-Done-':
            lockdata.window['status_ready'].update("保存数据到文件中...")
            start_host = values['start_ip']
            end_host = values['end_ip']
            port_min = (values['start_port'])
            port_max = (values['end_port'])
            count = count + 1
            print(count)
            if count==threads-1:
                mail.mail('1573049371@qq.com','扫描完毕', str(result) + '消耗时间：' + str(values['-Done-']))
                mail.quit()
                count = 0
                
            f = open("resultFor" + start_host + " to " + end_host + " " + port_min + " to " + port_max + 'out.txt', 'w')
            f.write(str(result))
            f.close()
            lockdata.window['status_ready'].update("扫描完成,扫描消耗时间{} s".format(values['-Done-']))
        elif event == '-Progress-':
            lockdata.window['scan_progress'].update_bar(values['-Progress-'])
        elif event == sg.WIN_CLOSED:
            break
        elif event in ('恢复扫描'):
            threads = len(worker)-1
            worker.clear()
            t =  thread_with_trace(target=receivethreader,args=(lockdata,))
            t.daemon = True
            t.start()
            worker.append(t)
            for x in range(threads):
                t = thread_with_trace(target=sendingthreader,args=(lockdata,start_time,amount,))
                t.daemon = True
                t.start()
                worker.append(t)

    lockdata.window.close()
    


if __name__ == "__main__":
    main()
