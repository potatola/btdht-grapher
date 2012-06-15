#coding=utf-8
import struct
import time
import thread
from project_definations import *
from Packet_bencode import Bencode
from Packet_eDonkey import EDonkey

UDP_ONLY = 1
BT_DHT_ONLY = 0
Delay_simulate = 0

class fake_ftxt:
        def write(self, somewords):
                pass
        def close(self):
                pass

class Dispach:

    def __init__(self, logLoc, resLoc='result.txt'):
        self.logLoc = logLoc
        self.resLoc = resLoc
        
        self.bencoder = Bencode()
        self.edonkeyer = EDonkey()
        
    def work(self, type = 1):
    #type = 0:draw; 1:extract
        fpcap = open(self.logLoc, 'rb')
        #ftxt = open(self.resLoc,'w')
        ftxt = fake_ftxt()
        
        self.bencoder.ftxt = ftxt

        string_data = fpcap.read()

        #pcap文件的数据包解析
        packet_num = 0
        last_time = 0
        pcap_packet_header = {}
        i =24
        while(i<len(string_data)):
            pac_info=packet_info()
            #数据包头各个字段
            pcap_packet_header['GMTtime'] = string_data[i:i+4]
            pcap_packet_header['MicroTime'] = string_data[i+4:i+8]
            pcap_packet_header['caplen'] = string_data[i+8:i+12]
            pcap_packet_header['len'] = string_data[i+12:i+16]
            #求出此包的包长len
            packet_len = struct.unpack('I',pcap_packet_header['len'])[0]
            if packet_num == 0:
                start_time_second = struct.unpack('I',pcap_packet_header['GMTtime'])[0]
                start_time_usecond = struct.unpack('I',pcap_packet_header['MicroTime'])[0]
            
            baseIp = i+16+14
            baseUdp = i+16+14+20
            #是否跳过非UDP包
            if (UDP_ONLY and string_data[baseIp+9].encode('hex') != '11'):
                i = i+ packet_len+16
                packet_num+=1
                continue
            #是否过滤非BT-DHT协议
            if BT_DHT_ONLY and string_data[baseUdp+8: baseUdp+9].encode('hex') != '64':
                i = i+ packet_len+16
                packet_num+=1
                continue

            ftxt.write("====packet No. "+str(packet_num+1)+'====\n')
            pac_info.pac_num = packet_num+1
            pac_info.size=struct.unpack('I', pcap_packet_header['len'])[0]
            ftxt.write('packet size: '+str(struct.unpack('I', pcap_packet_header['len'])[0])+'\n')
            # for key in ['GMTtime', 'MicroTime','caplen']:
                # ftxt.write(key+' : '+repr(pcap_packet_header[key])+'\n')
            utime=struct.unpack('I',pcap_packet_header['MicroTime'])[0] - start_time_usecond
            if utime < 0:
                utime = 1000000+utime
                pac_info.time=float(struct.unpack('I',pcap_packet_header['GMTtime'])[0] - start_time_second - 1) + float(utime)/1000000.0
            else:
                pac_info.time=float(struct.unpack('I',pcap_packet_header['GMTtime'])[0] - start_time_second) + float(utime)/1000000.0
            
            ftxt.write('Time: '+str(pac_info.time)+'\n')
            
            # sleep to simulate real process
            if type == 0 and Delay_simulate:
                # print 'packet %s sleep %f ---- %f - %f'%(str(packet_num+1), pac_info.time - last_time, pac_info.time, last_time)
                time.sleep(pac_info.time - last_time)
                # print 'week up'
                last_time = pac_info.time
            
            #以16进制打印数据部分
            # hex_data = string_data[i+16:i+16+packet_len].encode('hex')
            # j=0
            # count = 0
            # ftxt.write('hex_data:\n')
            # while (j<len(hex_data)):
                # ftxt.write(hex_data[j]+hex_data[j+1]+' ')
                # count += 1
                # if count == 8:
                    # ftxt.write(' ')
                # elif count == 16:
                    # count = 0
                    # ftxt.write('\n')
                # j+=2
            # ftxt.write('\n')
            #尝试分析数据
            #以太网层
            ftxt.write('==ethernet:\n')
            ftxt.write('    dst: 0x'+string_data[i+16: i+16+6].encode('hex')+'    src: 0x'+string_data[i+16+6: i+16+12].encode('hex')+'\n')
            ftxt.write('    type: 0x'+string_data[i+16+12: i+16+14].encode('hex')+'\n')
            #IP，在这里只判断协议类型和双方IP地址，忽略其他信息，忽略IPv6
            protocolType = {'01':'ICMP', '06':'TCP', '11':'UDP'}
            ftxt.write('==IP:\n')
            ftxt.write('Protocol: '+protocolType.get(string_data[baseIp+9].encode('hex'), '<unknown>')+'(0x'+string_data[baseIp+9].encode('hex')+')\n')
            src_IP = ''
            for ipPart in range(4):
                src_IP += '.'+str(int(string_data[baseIp+12+ipPart].encode('hex'), 16))
            src_IP = src_IP[1:]
            dst_IP = ''
            for ipPart in range(4):
                dst_IP += '.'+str(int(string_data[baseIp+16+ipPart].encode('hex'), 16))
            dst_IP = dst_IP[1:]
            pac_info.src_ip=src_IP
            pac_info.dst_ip=dst_IP
            ftxt.write('source: '+src_IP+'    destination: '+dst_IP+'\n')
            
            pac_info.src_port=int(string_data[baseUdp: baseUdp+2].encode('hex'), 16)
            pac_info.dst_port=int(string_data[baseUdp+2: baseUdp+4].encode('hex'), 16)
            ftxt.write('==UDP:\n')
            ftxt.write('    source port: '+str(int(string_data[baseUdp: baseUdp+2].encode('hex'), 16))+
                '    dst port: '+str(int(string_data[baseUdp+2: baseUdp+4].encode('hex'), 16))+'\n')
            udpLength = int(string_data[baseUdp+4: baseUdp+6].encode('hex'), 16)
            ftxt.write('    length: '+str(udpLength)+'\n')
            #这里开始解析bencode编码
            bencode = string_data[baseUdp+8: baseUdp+udpLength]
            # ftxt.write('bencode(raw): '+bencode+'\n')
            #递归解析bencode编码
            #try:
            self.bencoder.bencode_btdht(bencode, pac_info, type)
            
            #分析结束
            ftxt.write('\n\n')
            i = i+ packet_len+16
            packet_num+=1

        ftxt.close()
        fpcap.close()
        
        
if __name__ == '__main__':
    disp = Dispach('captured.pcap', 'diapach.log')
    disp.work()
