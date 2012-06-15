#coding=utf-8
'''
主要定义一个接收eDonkey格式编码的字符串，解析其中含义。
'''

# KADEMLIA (opcodes) (udp)
KADEMLIA2_REQ = 0x21
KADEMLIA2_RES = 0x29

logIO = open('eDonkeyDispach.log', 'w')

class eDonkeyDispach:
        
    def __init__(self):
        pass
        
    def processPacket(self, eDonkey):
        byType = eDonkey[0]
        
        if byType == KADEMLIA2_REQ:
            this.ProcessKademlia2Req(eDonkey[1:])
            
    def ProcessKademlia2Req(self, eDonkey):
        logIO.write('kademlia2_req')