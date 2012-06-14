#coding=utf-8
'''
此代码接受一段bencode代码，解析其中含义，分析相互关系
'''
from nodeView import *
import math
import sys
import __builtin__

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

Node_color = {'returned':'', 'responsed':'yellow', 'host':'green', 'timeout':'red', 'peers':'blue'}

class fake_dlog:
        def write(self, somewords):
                pass
        def close(self):
                pass

#解析bencode
class Bencode:

    def __init__(self):
        self.analysing = Analyser()
        self.ftxt=''
    #整个bencode包入口
    def bencode_btdht(self, bencode, pac_info, type = 1):
        self.pac={}    #用一个字典表示一个包
        self.pac['info']=pac_info
        try:
            self.bencode_dict(bencode, 0, 'BT-DHT Protocol')
        except:
            print sys.exc_info()[0], ':', sys.exc_info()[1]
            self.ftxt.write('======Error: unable to interpret bencode info!======\n\n')
            self.ftxt.write('the raw bencode is:\n'+repr(bencode))
            return
        self.ftxt.write('    the dict of packet we get is:\n        '+str(self.pac)+'\n')
        self.ftxt.write('    of which the \'info\' part is:\n        '+str(self.pac['info'].__dict__)+'\n')
        if 'a' in self.pac:
            if type == 0:
                self.analysing.new_request(self.pac)
            else:
                self.analysing.targetList(self.pac)
        elif type == 0:
                self.analysing.new_response(self.pac)
            
    #解析'd'字典类型
    def bencode_dict(self, bencode, offset, label):
        self.ftxt.write("%s : dictionary...\n" % (label))
        #skip the leading 'd'
        offset+=1
        #recursively decode a dictionary
        while bencode[offset] != 'e':
            offset = self.bencode_dict_entry(bencode, offset)
        #skip the ending 'e'
        offset+=1
        return offset
    #解析每个字典项    ，尤其是解析key-value对中的信息
    def bencode_dict_entry(self, bencode, offset):
        #key...
        offset, key = self.bencode_string(bencode, offset, 'key')
        #value...
        if bencode[offset] == 'd':
            offset = self.bencode_dict(bencode, offset, 'value')
        elif bencode[offset] == 'l':
            if key == 'e':
                offset, val = self.bencode_error(bencode, offset, 'value')
            elif key == 'values':
                offset, val = self.bencode_values(bencode, offset, 'value')
            else:
                offset, val = self.bencode_list(bencode, offset, 'value')
        elif bencode[offset] == 'i':
            offset, val = self.bencode_int(bencode, offset, 'value')
        else:
            if key == 'nodes':
                offset, val = self.bencode_nodes(bencode, offset, 'value')
            else:
                hex = key=='id' or key=='target' or key=='info_hash' or key=='t' or key=='v'
                offset, val = self.bencode_string(bencode, offset, 'value', hex)
                
        #向pac中保存提取到的信息，这里也体现了packet的字典结构中有哪些项目
        if key in ['t', 'v', 'y', 'id', 'q', 'target', 'ip', 'nodes', 'values', 'info_hash']:
            if key in ['y', 'ip', 'nodes', 'values', 'q']:
                self.pac[key]=val
            else:
                self.pac[key]=val.encode('hex')
        elif key in ['a', 'r']:
            self.pac[key] = 'Dict Value'
        return offset
    #字符串类型            
    def bencode_string(self, bencode, offset, label, hex=0):
        string_start = offset
        while bencode[offset] != ':':
            offset+=1
        string_len = int(bencode[string_start: offset])
        #skip the ':'
        offset+=1
        if hex == 1:
            self.ftxt.write("%s: %s\n" % (label, bencode[offset: offset+string_len].encode('hex')))
        else:
            self.ftxt.write("%s: %s\n" % (label, bencode[offset: offset+string_len]))
        return offset+string_len, bencode[offset: offset+string_len]
    #int类型    
    def bencode_int(self, bencode, offset, label):
        start_offset = offset+1
        while bencode[offset] != 'e':
            offset+=1
        self.ftxt.write("%s: %s\n" % (label, bencode[start_offset: offset]))
        return offset+1, bencode[start_offset: offset]
    #解析返回信息中的节点信息    
    def bencode_nodes(self, bencode, offset, label):
        node_index = 0
        nodes=[]
        string_start = offset
        while(bencode[offset] != ':'):
            offset+=1
        string_len = int(bencode[string_start: offset])
        #skip the ':'
        offset+=1
        
        #20 bytes id, 4 bytes ip, 2 bytes port
        while string_len >= 26:
            node={}
            node_index+=1
            id = bencode[offset: offset+20].encode('hex')
            ip = ''
            for i in range(4):
                ip += '.'+str(int(bencode[offset+20+i].encode('hex'), 16))
            ip = ip[1:]
            port = int(bencode[offset+24: offset+26].encode('hex'), 16)
            self.ftxt.write("%d    %s %s:%d\n" % (node_index, id, ip, port))
            node['id']=id
            node['ip']=ip
            node['port']=port
            nodes.append(node)
            
            string_len -= 26
            offset += 26
            
        return offset, nodes
    #解析出错信息（不知何用）
    def bencode_error(self, bencode, offset, label):
        offset += 1
        offset, error_id = self.bencode_int(bencode, offset, 'Error ID')
        offset, error_msg = self.bencode_string(bencode, offset, 'Error Message')
        self.ftxt.write("%s: error %s, %s\n" % (label, error_id, error_msg))
        return offset, ("error %s, %s", error_no, error_msg)
    #解析get_peers包的应答包中的peers信息
    def bencode_values(self, bencode, offset, label):
        peer_index = 0
        offset += 1
        values = []
        while bencode[offset] != 'e':
            string_len_start = offset
            while bencode[offset] != ':':
                offset += 1
            string_len = int(bencode[string_len_start: offset])
            offset += 1
            # 4 bytes ip, 2 bytes port
            while string_len >= 6:
                value = {}
                peer_index += 1
                ip = ''
                for i in range(4):
                    ip += '.'+str(int(bencode[offset+i].encode('hex'), 16))
                ip = ip[1:]
                port = int(bencode[offset+4: offset+6].encode('hex'), 16)
                value['ip'] = ip
                value['port'] = port
                values.append(value)
                self.ftxt.write("%d        %s:%d\n" % (peer_index, ip, port))
                string_len -= 6
                offset += 6
            if string_len > 0:
                offset += string_len
        return offset, values
        
    def bencode_list(self, bencode, offset, label):
        offset += 1
        one_byte = bencode[offset]
        while one_byte != 'e':
            if one_byte == 'i':
                offset, result = self.bencode_int(bencode, offset, 'Integer')
            elif one_byte == 'l':
                offset = self.bencode_list(bencode, offset, 'Sub-list')
            elif one_byte == 'd':
                offset = self.bencode_dict(bencode, offset, 'Sub-dict')
            else:
                offset, result = self.bencode_string(bencode, offset, 'String')
            one_byte = bencode[offset]
        return offset+1
    

class packet_info(object):
    ''''''
    time=0;    #float number 
    size=0;
    pac_num=0;
    src_ip=''; src_port=0; dst_ip=''; dst_port=0;    

class Analyser:
    '''collect all packets, draw the communication'''
    def __init__(self, canvas=None, main_window=None, type=1):
        #self.dlog=open('dialog.txt', 'w')
        self.dlog=fake_dlog()
    
        self.requests = {}    #存储所有请求的队列
        self.IPs_queried = [] # related dst IPs of one search
        self.nodes_by_ip = {} # instances of Node, maping ip to Node
        
        self.request_num = 0
        self.response_num = 0
        self.current_target = ''#target that most packets currently relate to
        self.last_target = ''
        self.start_time = 0
        self.user_target = ''#target that user choosed
        
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
