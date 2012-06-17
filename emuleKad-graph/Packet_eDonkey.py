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
KADEMLIA2_SEARCH_KEY_REQ = 0x33
KADEMLIA_SEARCH_RES = 0x38
KADEMLIA2_SEARCH_RES = 0x3b

kademlia_msgs = {
KADEMLIA_REQ    :   'KADEMLIA_REQ',
KADEMLIA2_REQ   :   'KADEMLIA2_REQ',
KADEMLIA_RES    :   'KADEMLIA_RES',
KADEMLIA2_RES   :   'KADEMLIA2_RES',
KADEMLIA2_SEARCH_KEY_REQ   :   'KADEMLIA2_SEARCH_KEY_REQ',
KADEMLIA_SEARCH_RES :   'KADEMLIA_SEARCH_RES',
KADEMLIA2_SEARCH_RES    :   'KADEMLIA2_SEARCH_RES'
}

logIO = open('Packet_eDonkey.log', 'w')


class EDonkey:
        
    def __init__(self):
        pass
        
    def dissect_handle(self, eDonkey):
        protocol = self.get_type('int8', eDonkey, 0)[0]
        if protocol in [EDONKEY_PROTO_KADEMLIA]:
            return True
        return False
        
    # 解析edonkey协议入口
    def dissect_edonkey_udp(self, eDonkey, pac_info):
        self.pac = {}
        self.pac['info'] = pac_info
    
        protocol = self.get_type('int8', eDonkey, 0)[0]
        msgType = self.get_type('int8', eDonkey, 1)[0]
        
        if protocol in [EDONKEY_PROTO_KADEMLIA]:
            self.pac['protocol'] = protocol
            self.pac['message_type'] = msgType
            offset = self.dissect_kademlia_udp_message(eDonkey, msgType, EDONKEY_UDP_HEADER_LENGTH)
            
        self.write_log()
        return
        
    def dissect_kademlia_udp_message(self, eDonkey, msg_type, offset):
        # 更近节点请求
        if msg_type in [KADEMLIA_REQ, KADEMLIA2_REQ]:
            type, offset = self.get_type('int8', eDonkey, offset)
            self.pac['request_type'] = type
            self.pac['target_id'], offset = self.get_type('ID', eDonkey, offset)
            self.pac['recipient_id'], offset = self.get_type('ID', eDonkey, offset)
        
        # 节点信息返回
        if msg_type in [KADEMLIA_RES]:
            self.pac['target_id'], offset = self.get_type('ID', eDonkey, offset)
            self.pac['peers'], offset = self.dissect_edonkey_list(eDonkey, offset, 1, 'peer')
            
        # 节点信息返回
        if msg_type in [KADEMLIA2_RES]:
            self.pac['target_id'], offset = self.get_type('ID', eDonkey, offset)
            self.pac['peers'], offset = self.dissect_edonkey_list(eDonkey, offset, 1, 'peer')
            
        # 请求资源信息
        if msg_type in [KADEMLIA2_SEARCH_KEY_REQ]:
            self.pac['target_id'], offset = self.get_type('ID', eDonkey, offset)
            self.pac['start_position'], offset = self.get_type('int16', eDonkey, offset)
            
        # 资源信息返回
        if msg_type in [KADEMLIA_SEARCH_RES]:
            # target
            self.pac['target_id'], offset = self.get_type('ID', eDonkey, offset)
            # result list
            self.pac['results'], offset = self.dissect_edonkey_list(eDonkey, offset, 2, 'result')
        
        # 资源信息返回
        if msg_type in [KADEMLIA2_SEARCH_RES]:
            # sender
            self.pac['sender_id'], offset = self.get_type('ID', eDonkey, offset)
            # target
            self.pac['target_id'], offset = self.get_type('ID', eDonkey, offset)
            # result list
            self.pac['results'], offset = self.dissect_edonkey_list(eDonkey, offset, 2, 'result')
            
            
    def dissect_edonkey_list(self, eDonkey, offset, listnum_length, dissect_type): #listnum_length存储占字节数,但是不知道除了一字节还有什么
        if listnum_length == 1:
            listnum, offset = self.get_type('int8', eDonkey, offset)
        elif listnum_length == 2:
            listnum, offset = self.get_type('int16', eDonkey, offset)
        
        res_list = []
        for i in range(listnum):
            res_item, offset = self.get_type(dissect_type, eDonkey, offset)
            res_list.append(res_item)
        return res_list, offset
        
        
    # 从eDonkey流中提取给定类型数据
    def get_type(self, type, eDonkey, offset):
        if type == 'int8':
            return int(eDonkey[offset].encode('hex'), 16), offset+1
        if type == 'int16':
            return int(eDonkey[offset:offset+1].encode('hex'), 16), offset+2
        if type == 'ID':
            return eDonkey[offset:offset+ID_LENGTH].encode('hex'), offset+ID_LENGTH
        if type == 'ip':
            ip = [0, 0, 0, 0]
            ip[0], offset = self.get_type('int8', eDonkey, offset)
            ip[1], offset = self.get_type('int8', eDonkey, offset)
            ip[2], offset = self.get_type('int8', eDonkey, offset)
            ip[3], offset = self.get_type('int8', eDonkey, offset)
            ip_str = ''
            for i in range(3):
                ip_str += str(ip[i])+'.'
            ip_str += str(ip[i])
            return ip_str, offset
        if type == 'peer':
            peer = {}
            peer['peer_id'], offset = self.get_type('ID', eDonkey, offset)
            peer['ip'], offset = self.get_type('ip', eDonkey, offset)
            peer['udp_port'], offset = self.get_type('int16', eDonkey, offset)
            peer['tcp_port'], offset = self.get_type('int16', eDonkey, offset)
            peer['kad_version'], offset = self.get_type('int8', eDonkey, offset)
            return peer, offset
        if type == 'result':
            results = {}
            results['kademlia_hash'], offset = self.get_type('ID', eDonkey, offset)
            # tag list
            results['tags'], offset = self.dissect_edonkey_list(eDonkey, offset, 1, 'tag')
            return results, offset
        if type == 'tag':
            return 'tag not dissected yet', offset
            tag = {}
            tag['type'], offset = self.get_type('int8', eDonkey, offset)
            tag['tag_name_length'], offset = self.get_type('int16', eDonkey, offset)
            if tag_name_length != 1:
                print 'attention! an tag_name_length not 1 appears!'
            # 如果tag_name_length不是1,这里就是错误的!
            tag['tag_name'], offset = self.get_type('int8', eDonkey, offset)
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        
    # 协议内容统一写入log文件
    def write_log(self):
        logIO.write("====packet No.%d  at %f(s)\n" % (self.pac['info'].pac_num, self.pac['info'].time))
        logIO.write("   src_ip:%s    dst_ip:%s\n" % (self.pac['info'].src_ip, self.pac['info'].dst_ip))
    
        # ===================
        if self.pac['message_type'] in [KADEMLIA_REQ, KADEMLIA2_REQ]:
            logIO.write(
'''    message type : %s
    request type : %d
    target id    : %s
    recipient id : %s
''' % (kademlia_msgs[self.pac['message_type']], self.pac['request_type'], self.pac['target_id'], self.pac['recipient_id']))

        # ===================
        elif self.pac['message_type'] in [KADEMLIA_RES, KADEMLIA2_RES]:
            logIO.write(
'''    message type : %s
    target id : %s
    peer list size : %d
''' % (kademlia_msgs[self.pac['message_type']], self.pac['target_id'], len(self.pac['peers'])))
            for i in range(len(self.pac['peers'])):
                peer = self.pac['peers'][i]
                logIO.write(
'''      peer[%d/%d]
        peer id : %s
        ip : %s
        udp port : %d
        tcp port : %d
        kad version : %d
''' % (i, len(self.pac['peers']), peer['peer_id'], peer['ip'], peer['udp_port'], peer['tcp_port'], peer['kad_version']))

        # ===================
        elif self.pac['message_type'] in [KADEMLIA2_SEARCH_KEY_REQ]:
            logIO.write(
'''    message type : %s
    target id : %s
    start position : %d
''' % (kademlia_msgs[self.pac['message_type']], self.pac['target_id'], self.pac['start_position']))

        # ===================
        elif self.pac['message_type'] in [KADEMLIA_SEARCH_RES, KADEMLIA2_SEARCH_RES]:
            if self.pac['message_type'] in [KADEMLIA2_SEARCH_RES]:
                logIO.write("   sender id : %s\n" % self.pac['sender_id'])
            logIO.write(
'''    target id : %s
    result list size : %d
''' % (self.pac['target_id'], len(self.pac['results'])))
            for i in range(len(self.pac['results'])):
                result = self.pac['results'][i]
                logIO.write(
'''      result[%d/%d]
        kademlia hash : %s
        tag list size : %d
''' % (i, len(self.pac['results']), result['kademlia_hash'], len(result['tags'])))

        logIO.write('\n')