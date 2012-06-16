#coding=utf-8
'''
主要定义一个接收eDonkey格式编码的字符串，解析其中含义。
'''
from project_definations import *


EDONKEY_UDP_HEADER_LENGTH = 2
ID_LENGTH = 16

# KADEMLIA (opcodes) (udp)
KADEMLIA2_REQ = 0x21
KADEMLIA2_RES = 0x29
EDONKEY_PROTO_EDONKEY = 0xe3
EDONKEY_PROTO_KADEMLIA = 0xe4
KADEMLIA_REQ = 0x20
KADEMLIA2_REQ = 0x21
KADEMLIA_RES = 0x28
KADEMLIA2_RES = 0x29

kademlia_msgs = {
KADEMLIA_REQ    :   'KADEMLIA_REQ',
KADEMLIA2_REQ   :   'KADEMLIA2_REQ',
KADEMLIA_RES    :   'KADEMLIA_RES',
KADEMLIA2_RES   :   'KADEMLIA2_RES'
}

logIO = open('Packet_eDonkey.log', 'w')

def get_type(type, eDonkey, offset):
    if type == 'int8':
        return int(eDonkey[offset].encode('hex'), 16), offset+1
    if type == 'int16':
        return int(eDonkey[offset:offset+1].encode('hex'), 16), offset+2
    if type == 'ID':
        return eDonkey[offset:offset+ID_LENGTH].encode('hex'), offset+ID_LENGTH
    if type == 'ip':
        ip = [0, 0, 0, 0]
        ip[0], offset = get_type('int8', eDonkey, offset)
        ip[1], offset = get_type('int8', eDonkey, offset)
        ip[2], offset = get_type('int8', eDonkey, offset)
        ip[3], offset = get_type('int8', eDonkey, offset)
        ip_str = ''
        for i in range(3):
            ip_str += str(ip[i])+'.'
        ip_str += str(ip[i])
        return ip_str, offset
    if type == 'peer':
        peer = {}
        peer['peer_id'], offset = get_type('ID', eDonkey, offset)
        peer['ip'], offset = get_type('ip', eDonkey, offset)
        peer['udp_port'], offset = get_type('int16', eDonkey, offset)
        peer['tcp_port'], offset = get_type('int16', eDonkey, offset)
        peer['kad_version'], offset = get_type('int8', eDonkey, offset)
        return peer, offset

class EDonkey:
        
    def __init__(self):
        pass
        
    def dissect_handle(self, eDonkey):
        protocol = get_type('int8', eDonkey, 0)[0]
        if protocol in [EDONKEY_PROTO_KADEMLIA]:
            return True
        return False
        
    # 解析edonkey协议入口
    def dissect_edonkey_udp(self, eDonkey, pac_info):
        self.pac = {}
        self.pac['info'] = pac_info
        
        logIO.write("====packet No.%d  at %f(s)\n" % (pac_info.pac_num, pac_info.time))
    
        protocol = get_type('int8', eDonkey, 0)[0]
        msgType = get_type('int8', eDonkey, 1)[0]
        
        if protocol in [EDONKEY_PROTO_KADEMLIA]:
            self.pac['protocol'] = protocol
            self.pac['message_type'] = msgType
            offset = self.dissect_kademlia_udp_message(eDonkey, msgType, EDONKEY_UDP_HEADER_LENGTH)
            
        logIO.write('\n\n')
        return
        
    def dissect_kademlia_udp_message(self, eDonkey, msg_type, offset):
        # 请求
        if msg_type in [KADEMLIA_REQ, KADEMLIA2_REQ]:
            type, offset = get_type('int8', eDonkey, offset)
            self.pac['request_type'] = type
            self.pac['target_id'], offset = get_type('ID', eDonkey, offset)
            self.pac['recipient_id'], offset = get_type('ID', eDonkey, offset)
        
        if msg_type in [KADEMLIA_RES]:
            self.pac['target_id'], offset = get_type('ID', eDonkey, offset)
            self.pac['peers'], offset = self.dissect_edonkey_list(eDonkey, offset, 1)
            
        if msg_type in [KADEMLIA2_RES]:
            self.pac['target_id'], offset = get_type('ID', eDonkey, offset)
            self.pac['peers'], offset = self.dissect_edonkey_list(eDonkey, offset, 1)
            
            
        self.write_log()
            
    def dissect_edonkey_list(self, eDonkey, offset, listnum_length): #listnum_length存储占字节数,但是不知道除了一字节还有什么
        if listnum_length == 1:
            listnum, offset = get_type('int8', eDonkey, offset)
        self.pac['peer_list_size'] = listnum
        
        peers = []
        for i in range(listnum):
            peer, offset = get_type('peer', eDonkey, offset)
            peers.append(peer)
        return peers, offset
        
    # 协议内容统一写入log文件
    def write_log(self):
        if self.pac['message_type'] in [KADEMLIA_REQ, KADEMLIA2_REQ]:
            logIO.write(
'''    message type : %s
    request type : %d
    target id    : %s
    recipient id : %s
''' % (kademlia_msgs[self.pac['message_type']], self.pac['request_type'], self.pac['target_id'], self.pac['recipient_id']))

        elif self.pac['message_type'] in [KADEMLIA_RES, KADEMLIA2_RES]:
            logIO.write(
'''    message type : %s
    target id : %s
    peer list size : %d
''' % (kademlia_msgs[self.pac['message_type']], self.pac['target_id'], self.pac['peer_list_size']))
            for i in range(self.pac['peer_list_size']):
                peer = self.pac['peers'][i]
                logIO.write(
'''      peer[%d/%d]
        peer id : %s
        ip : %s
        udp port : %d
        tcp port : %d
        kad version : %d
''' % (i, self.pac['peer_list_size'], peer['peer_id'], peer['ip'], peer['udp_port'], peer['tcp_port'], peer['kad_version']))