#coding=utf-8
'''
画图
'''
from nodeView import *
from project_definations import *
from  xml.dom import  minidom
import math
import sys 
reload(sys) 
sys.setdefaultencoding('utf8')
import __builtin__

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s


class Analyser:
    '''collect all packets, draw the communication'''
    def __init__(self, canvas=None, main_window=None, type=1):
    
        self.requests = {}    #存储所有请求的队列
        self.IPs_queried = [] # related dst IPs of one search
        self.nodes_by_ip = {} # instances of Node, maping ip to Node
        
        self.request_num = 0
        self.response_num = 0
        self.current_target = ''#target that most packets currently relate to
        self.last_target = ''
        self.start_time = -1
        self.user_target = ''#target that user choosed
        
        self.targets = []
        self.ip2id = {}
        
        #画布
        if canvas != None:
            self.canvas = canvas
            self.main_window = main_window
            self.Scene_uptop = __builtin__.__dict__['Scene_height']
            self.show_percentage = 0
            
            self.canvas.scene().clear()
            
            self.canvas.scene().addLine(5, __builtin__.__dict__['Scene_height']-5, __builtin__.__dict__['Scene_width'], __builtin__.__dict__['Scene_height']-5)
            self.canvas.scene().addLine(5, __builtin__.__dict__['Scene_height']-5, 5, 5)
            
            example_node = Node(self.canvas, Node_color['requested'], self.main_window)
            example_node.setSelfDate(_fromUtf8('node type'), _fromUtf8('node that have been quested(if not line points to it, it may be in the bucket)'))
            self.canvas.scene().addItem(example_node)
            example_node.setPos(__builtin__.__dict__['Scene_width'], 30)
            example_node = Node(self.canvas, Node_color['returned'], self.main_window)
            example_node.setSelfDate(_fromUtf8('node type'), _fromUtf8('node returned by other nodes'))
            self.canvas.scene().addItem(example_node)
            example_node.setPos(__builtin__.__dict__['Scene_width'], 40)
            example_node = Node(self.canvas, Node_color['responsed'], self.main_window)
            example_node.setSelfDate(_fromUtf8('node type'), _fromUtf8('node with peer infomation only'))
            self.canvas.scene().addItem(example_node)
            example_node.setPos(__builtin__.__dict__['Scene_width'], 50)
            example_node = Node(self.canvas, Node_color['peers'], self.main_window)
            example_node.setSelfDate(_fromUtf8('node type'), _fromUtf8('node with value infomation'))
            self.canvas.scene().addItem(example_node)
            example_node.setPos(__builtin__.__dict__['Scene_width'], 60)
            example_node = Node(self.canvas, Node_color['taged'], self.main_window)
            example_node.setSelfDate(_fromUtf8('node type'), _fromUtf8('node taged in the .xml'))
            self.canvas.scene().addItem(example_node)
            example_node.setPos(__builtin__.__dict__['Scene_width'], 70)
            
            if type == 0:
                #print 'the target Value is \'%s\'\n' % main_window.List.selectedItems()[0].text()
                self.user_target = str(main_window.List.selectedItems()[0].text())
        else:
            self.user_target = 'af44869af3ac547adc8ee59af38ea0a74b641991'
            
        # ip列表显示特殊颜色
        self.taged_ips = []
        if type == 0:
            try:
                doc = minidom.parse('serviceip.xml') 
                root = doc.documentElement
                ips = root.getElementsByTagName('ip')
                for ip in ips:
                    self.taged_ips.append(ip.getElementsByTagName('outsideip')[0].firstChild.nodeValue)
            except:
                pass
            
    def edonkey_target_list(self, request):
        target = request['target_id']
            
        if not target in self.targets:
            self.targets.append(target)
            self.main_window.List.insertRow(self.main_window.ListCount)
            self.main_window.ListCount += 1
            newItem = QTableWidgetItem(_fromUtf8(target))
            self.main_window.List.setItem(self.main_window.ListCount-1, 0, newItem)
            # newItem = QTableWidgetItem(_fromUtf8('type'))
            # self.main_window.List.setItem(self.main_window.ListCount-1, 1, newItem)
            
            # distance = math.log((int(str(target), 16)^int(str(self.self_id), 16)), 2)
            # newItem = QTableWidgetItem(_fromUtf8(str(distance)))
            # self.main_window.List.setItem(self.main_window.ListCount-1, 2, newItem)
            
    def edonkey_request(self, request):
        if request['target_id'] != self.user_target:
            return
        elif self.start_time == -1:
            self.start_time = request['info'].time
        # 记录被查询节点的ip对应的id号
        if request['message_type'] in [KADEMLIA_REQ, KADEMLIA2_REQ]:
            self.ip2id[request['info'].dst_ip] = request['recipient_id']
            dst_id = self.ip2id[request['info'].dst_ip]
        else:
            dst_id = self.ip2id[request['info'].dst_ip]
        # draw the requested node
        if request['info'].dst_ip not in self.nodes_by_ip:
            tmp_node = Node(self.canvas, Node_color['requested'], self.main_window)
            self.canvas.scene().addItem(tmp_node)
            self.nodes_by_ip[request['info'].dst_ip] = tmp_node
            tx = (request['info'].time - self.start_time) / __builtin__.__dict__['IGNORE_TIME'] * __builtin__.__dict__['Scene_width']
            # count log if ty > 1
            ty = int(dst_id, 16)^int(str(self.user_target), 16)
            tmp_node.setSelfDate('requested in pac_num', request['info'].pac_num)
            tmp_node.setSelfDate('ip', request['info'].dst_ip)
            tmp_node.setSelfDate('id', dst_id)
            tmp_node.data['distance'] = str(int(dst_id  , 16)^int(str(self.user_target), 16)).zfill(40)
            ty = self.adjust_ty(ty, tx)
            tmp_node.setPos(tx, ty)
            self.adjust_color(tmp_node, request['info'].dst_ip)
            src_node = tmp_node
            
    def edonkey_response(self, response):
        if response['target_id'] != self.user_target:
            return
        # if response['message_type'] in [KADEMLIA_RES, KADEMLIA2_RES, KADEMLIA_SEARCH_RES]:
            # src_id = self.ip2id[response['info'].src_ip]
        # else:
            # src_id = response['sender_id']
        if 'sender_id' in response:
            src_id = response['sender_id']
        elif response['info'].src_ip in self.ip2id:
            src_id = self.ip2id[response['info'].src_ip]
        else:
            print 'error: ip not seen before, no id can be matched!'
            
        # determine the 'src' node
        if response['info'].src_ip in self.nodes_by_ip: # a node that have been returned earlier
            src_node = self.nodes_by_ip[response['info'].src_ip]
            src_node.setInitColor(Node_color['responsed'])
            src_node.setSelfDate('answered in pac_num', response['info'].pac_num)
        else:   # new node: 1.host node, 2.incomplete process(missing earlier infomation)
            tmp_node = Node(self.canvas, Node_color['host'], self.main_window)
            self.canvas.scene().addItem(tmp_node)
            self.nodes_by_ip[response['info'].src_ip] = tmp_node
            tx = (response['info'].time - self.start_time) / __builtin__.__dict__['IGNORE_TIME'] * __builtin__.__dict__['Scene_width']
            # count log if ty > 1
            ty = int(src_id, 16)^int(str(self.user_target), 16)
            tmp_node.setSelfDate('answered in pac_num', response['info'].pac_num)
            tmp_node.setSelfDate('ip', response['info'].src_ip)
            tmp_node.setSelfDate('id', src_id)
            tmp_node.data['distance'] = str(int(src_id, 16)^int(str(self.user_target), 16)).zfill(40)
            ty = self.adjust_ty(ty, tx)
            tmp_node.setPos(tx, ty)
            self.adjust_color(tmp_node, response['info'].src_ip)
            src_node = tmp_node
            
        # 如果返回的是更近的nodes, 画出这些nodes
        if response['message_type'] in [KADEMLIA_RES, KADEMLIA2_RES]:
            src_node.setSelfDate('peers', response['peers'])
            src_node.setInitColor(Node_color['responsed'])
            for peer in response['peers']:
                if not peer['ip'] in self.nodes_by_ip:
                    tmp_node = Node(self.canvas, Node_color['returned'], self.main_window)
                    self.canvas.scene().addItem(tmp_node)
                    
                    tmp_node.setSelfDate('returned in pac_num', response['info'].pac_num)
                    tmp_node.setSelfDate('id', peer['peer_id'])
                    tmp_node.setSelfDate('ip', peer['ip'])
                    tmp_node.setSelfDate('udp_port', peer['udp_port'])
                    tmp_node.setSelfDate('found_time', response['info'].time)
                    
                    self.adjust_color(tmp_node, peer['ip'])
        
                    tx = (response['info'].time - self.start_time) / __builtin__.__dict__['IGNORE_TIME'] * __builtin__.__dict__['Scene_width']
                    # count log if ty > 1
                    ty = int(str(peer['peer_id']), 16)^int(str(self.user_target), 16)
                    tmp_node.data['distance'] = ty.__hex__()[2:].zfill(40)
                    ty = self.adjust_ty(ty, tx)
                    tmp_node.setPos(tx, ty)
                
                    self.nodes_by_ip[peer['ip']] = tmp_node
                    
                    self.canvas.scene().addItem(Edge(src_node, tmp_node))
                else:
                    self.canvas.scene().addItem(Edge(src_node, self.nodes_by_ip[peer['ip']]))
                    
                    
                    self.canvas.update()
                    self.main_window.update()
                    
        if response['message_type'] in [KADEMLIA_SEARCH_RES, KADEMLIA2_SEARCH_RES]:
            src_node.setSelfDate('results', response['results'])
            src_node.setInitColor(Node_color['peers'])
            

    # split the scene into 10 parts, show only the bottom one initially, when ty reaches the top, show one more part.
    def adjust_ty(self, ty, tx):
        #the 'ty' passed in is the result of xor
        if ty > 1:
            ty = math.log(ty, 2) / 128 * __builtin__.__dict__['Scene_height']
        while ty < self.Scene_uptop:
            self.Scene_uptop -= __builtin__.__dict__['Scene_height']/14
            self.show_percentage += 10
            # a vertical line indicating that it'll show one more part.
            tempText = self.canvas.scene().addText(_fromUtf8(str(self.show_percentage)+'%'))
            tempText.setPos(tx, 15 + self.show_percentage)
            self.canvas.scene().addLine(tx, 10, tx, __builtin__.__dict__['Scene_height'])
        ty = ((ty - self.Scene_uptop) / (__builtin__.__dict__['Scene_height'] - self.Scene_uptop)) * __builtin__.__dict__['Scene_height']
        ty = __builtin__.__dict__['Scene_height'] - ty
        return ty
        
    # given a list of ips(in a xml file), tag all nodes with ip in the list
    def adjust_color(self, node, node_ip):
        if node_ip in self.taged_ips:
            node.setInitColor(Node_color['taged'])

if __name__ == '__main__':
    #测试代码
    print 'test message.py'
