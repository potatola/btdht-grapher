#coding=utf-8
'''
主要定义一个接收eDonkey格式编码的字符串，解析其中含义。
'''

# KADEMLIA (opcodes) (udp)
KADEMLIA2_REQ = 0x21
KADEMLIA2_RES = 0x29
EDONKEY_PROTO_EDONKEY = 0xe3
EDONKEY_PROTO_KADEMLIA = 0xe4

logIO = open('eDonkeyDispach.log', 'w')

class EDonkey:
        
    def __init__(self):
        pass
        
    def dissect_handle(self, eDonkey):
        protocol = eDonkey[offset]
        print protocol
        
    def dissect_edonkey_udp(self, eDonkey, offset):
        protocol = eDonkey[offset]
        msgType = eDonkey[offset+1]
        
        print protocol