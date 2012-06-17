#coding=utf-8
'''
画图
'''
from nodeView import *
from project_definations import *
import math
import sys
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
            
            if type == 0:
                #print 'the target Value is \'%s\'\n' % main_window.List.selectedItems()[0].text()
                self.user_target = str(main_window.List.selectedItems()[0].text())
        else:
            self.user_target = 'af44869af3ac547adc8ee59af38ea0a74b641991'
            
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
            tmp_node.setSelfDate('ip', request['info'].src_ip)
            tmp_node.setSelfDate('id', dst_id)
            tmp_node.data['distance'] = str(int(dst_id  , 16)^int(str(self.user_target), 16)).zfill(40)
            ty = self.adjust_ty(ty, tx)
            tmp_node.setPos(tx, ty)
            src_node = tmp_node
            
    def edonkey_response(self, response):
        if response['target_id'] != self.user_target:
            return
        if response['message_type'] in [KADEMLIA_RES, KADEMLIA2_RES]:
            src_id = self.ip2id[response['info'].src_ip]
        else:
            src_id = response['sender_id']
            
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
            src_node = tmp_node
            
        # 如果返回的是更近的nodes, 画出这些nodes
        if response['message_type'] in [KADEMLIA_RES, KADEMLIA2_RES]:
            src_node.setSelfDate('peers', response['peers'])
            for peer in response['peers']:
                if not peer['ip'] in self.nodes_by_ip:
                    tmp_node = Node(self.canvas, Node_color['returned'], self.main_window)
                    self.canvas.scene().addItem(tmp_node)
                    
                    tmp_node.setSelfDate('returned in pac_num', response['info'].pac_num)
                    tmp_node.setSelfDate('id', peer['peer_id'])
                    tmp_node.setSelfDate('ip', peer['ip'])
                    tmp_node.setSelfDate('udp_port', peer['udp_port'])
                    tmp_node.setSelfDate('found_time', response['info'].time)
        
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
            
            
            
            
    # ==============       old       ======================================================================    
    def new_request(self, request):
        if request['q'] == 'ping':    #ignore 'ping' request
            return
        elif request['q'] == 'announce_peer':    #how to deal?
            return
        else:
            if 'target' in request:
                target = request['target']
            else:
                target = request['info_hash']
            self.last_target = self.current_target
            self.current_target = target
            
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if target != self.user_target:
            return
        self.dlog.write('packet %d -- target ip = %s added.\n' % (request['info'].pac_num, request['info'].dst_ip))
        self.IPs_queried.append(request['info'].dst_ip)
            
        if not target in self.requests:
            self.requests[target] = []
            # timing independently for each search
            self.start_time = request['info'].time
            #print "target changed from %s to %s at the %d request\n" % (self.last_target, target, self.request_num)
        self.requests[target].append(request)
        self.request_num += 1
        
        #保存时间超过IGNORE_TIME仍未被答复的认为超时，不再处理
        for item in self.requests[target]:
            if request['info'].time - item['info'].time >= __builtin__.__dict__['IGNORE_TIME']:
                self.requests[target].remove(item)
        
    def new_response(self, response):
        #only responses for the particular conversation matter
        if not response['info'].src_ip in self.IPs_queried:
            return
            
        self.response_num += 1
        for item in reversed(self.requests[self.user_target]):
            #only response for a previous query
            if item['info'].dst_ip == response['info'].src_ip:
                self.dlog.write('====a conversation detected at time %f, packet %d to packet %d====\n' 
                    % (item['info'].time, response['info'].pac_num, item['info'].pac_num))
                if 'target' in item:
                    self.dlog.write(item['info'].src_ip+'--'+item['q']+'--'+item['info'].dst_ip+' for node \'%s\'\n' % (item['target']))
                else:
                    self.dlog.write(item['info'].src_ip+'--'+item['q']+'--'+item['info'].dst_ip+' for info_hash \'%s\'\n' % (item['info_hash']))
                self.dlog.write('anwsered by \'%s\'\n' % (response['id']))
                self.dlog.write('transaction ID: '+item['t']+'\n')
                self.dlog.write('    the dict of packet we get is:\n        '+str(response)+'\n')
                self.dlog.write('    of which the \'info\' part is:\n        '+str(response['info'].__dict__)+'\n')
                
                #draw lines
                # determine the 'src' node
                if response['info'].src_ip in self.nodes_by_ip: # a node that have been returned earlier
                    src_node = self.nodes_by_ip[response['info'].src_ip]
                    src_node.setInitColor(Node_color['responsed'])
                else:   # new node: 1.host node, 2.incomplete process(missing earlier infomation)
                    tmp_node = Node(self.canvas, Node_color['host'], self.main_window)
                    self.canvas.scene().addItem(tmp_node)
                    self.nodes_by_ip[response['info'].src_ip] = tmp_node
                    tx = (response['info'].time - self.start_time) / __builtin__.__dict__['IGNORE_TIME'] * __builtin__.__dict__['Scene_width']
                    # count log if ty > 1
                    ty = int(str(response['id']), 16)^int(str(self.user_target), 16)
                    tmp_node.data['distance'] = str(int(str(response['id']), 16)^int(str(self.user_target), 16)).zfill(40)
                    ty = self.adjust_ty(ty, tx)
                    tmp_node.setPos(tx, ty)
                    src_node = tmp_node
                    
                src_node.setSelfDate('id', response['id'])
                src_node.setSelfDate('ip', response['info'].src_ip)
                src_node.setSelfDate('port', response['info'].src_port)
                
                if 'nodes' in response:
                    self.dlog.write('========response with nodes:\n')
                    src_node.setSelfDate('nodes', response['nodes'])
                    for node in response['nodes']:
                        self.dlog.write('ip='+node['ip']+'      id='+node['id']+'       port='+str(node['port'])+'\n')
                        
                        if not node['ip'] in self.nodes_by_ip:
                            tmp_node = Node(self.canvas, Node_color['returned'], self.main_window)
                            self.canvas.scene().addItem(tmp_node)
                            
                            tmp_node.setSelfDate('id', node['id'])
                            tmp_node.setSelfDate('ip', node['ip'])
                            tmp_node.setSelfDate('port', node['port'])
                            tmp_node.setSelfDate('found_time', response['info'].time)
                
                            tx = (response['info'].time - self.start_time) / __builtin__.__dict__['IGNORE_TIME'] * __builtin__.__dict__['Scene_width']
                            # count log if ty > 1
                            ty = int(str(node['id']), 16)^int(str(self.user_target), 16)
                            tmp_node.data['distance'] = ty.__hex__()[2:].zfill(40)
                            ty = self.adjust_ty(ty, tx)
                            tmp_node.setPos(tx, ty)
                        
                            self.nodes_by_ip[node['ip']] = tmp_node
                            
                            self.canvas.scene().addItem(Edge(src_node, tmp_node))
                            
                            self.canvas.update()
                            self.main_window.update()
                            
                            self.dlog.write('distance is %f\n' % (ty/__builtin__.__dict__['Scene_height']))
                if 'values' in response:
                    src_node.setSelfDate('values', response['values'])
                    src_node.setInitColor(Node_color['peers'])
                    self.dlog.write('========response with values:\n')
                if not ('nodes' in response or 'values' in response):
                    self.dlog.write("====proval that node {%s} is alive====\n\n" % response['id'])
                    
                self.dlog.write('\n')
                self.requests[self.user_target].remove(item)
                break
                
    def targetList(self, request):
        self.self_id_flag = False
        if request['q'] == 'ping':    #ignore 'ping' request
            return
        elif request['q'] == 'announce_peer':    #how to deal?
            return
        else:
            if 'target' in request:
                target = request['target']
                type = 'find_node'
            else:
                target = request['info_hash']
                type = 'get_peers'
            if not self.self_id_flag:
                self.self_id = request['id']
                self.main_window.portLineEdit.setText(_fromUtf8(self.self_id))
                self.self_id_flag = True
            
        self.dlog.write('packet %d -- target ip = %s added.\n' % (request['info'].pac_num, request['info'].dst_ip))
            
        if not target in self.requests:
            self.requests[target] = []
            self.main_window.List.insertRow(self.main_window.ListCount)
            self.main_window.ListCount += 1
            newItem = QTableWidgetItem(_fromUtf8(target))
            self.main_window.List.setItem(self.main_window.ListCount-1, 0, newItem)
            newItem = QTableWidgetItem(_fromUtf8(type))
            self.main_window.List.setItem(self.main_window.ListCount-1, 1, newItem)
            
            distance = math.log((int(str(target), 16)^int(str(self.self_id), 16)), 2)
            newItem = QTableWidgetItem(_fromUtf8(str(distance)))
            self.main_window.List.setItem(self.main_window.ListCount-1, 2, newItem)
        
        #保存时间超过IGNORE_TIME仍未被答复的认为超时，不再处理
        for item in self.requests[target]:
            if request['info'].time - item['info'].time >= __builtin__.__dict__['IGNORE_TIME']:
                self.requests[target].remove(item)
        
    # split the scene into 10 parts, show only the bottom one initially, when ty reaches the top, show one more part.
    def adjust_ty(self, ty, tx):
        #the 'ty' passed in is the result of xor
        if ty > 1:
            ty = math.log(ty, 2) / 160 * __builtin__.__dict__['Scene_height']
        while ty < self.Scene_uptop:
            self.Scene_uptop -= __builtin__.__dict__['Scene_height']/10
            self.show_percentage += 10
            # a vertical line indicating that it'll show one more part.
            tempText = self.canvas.scene().addText(_fromUtf8(str(self.show_percentage)+'%'))
            tempText.setPos(tx, 20)
            self.canvas.scene().addLine(tx, 10, tx, __builtin__.__dict__['Scene_height'])
        ty = ((ty - self.Scene_uptop) / (__builtin__.__dict__['Scene_height'] - self.Scene_uptop)) * __builtin__.__dict__['Scene_height']
        ty = __builtin__.__dict__['Scene_height'] - ty
        return ty

if __name__ == '__main__':
    #测试代码
    print 'test message.py'
