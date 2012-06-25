#!/usr/bin/env python
# -*- coding: utf-8 -*-

#############################################################################
##
## 画节点关系图,这里提供了基本的节点,边和画布的类
##
#############################################################################


import math
from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import *
from PyQt4.QtGui import *
import __builtin__

__builtin__.__dict__['IGNORE_TIME'] = 30    #ignore reply packets after 10 seconds

__builtin__.__dict__['Scene_time_multi'] = 40
__builtin__.__dict__['Scene_height'] = 440
__builtin__.__dict__['Scene_width'] = __builtin__.__dict__['IGNORE_TIME'] * __builtin__.__dict__['Scene_time_multi']
__builtin__.__dict__['Scene_uptop'] = 440

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

class Edge(QtGui.QGraphicsItem):
    Pi = math.pi
    TwoPi = 2.0 * Pi

    Type = QtGui.QGraphicsItem.UserType + 2	#Type变量唯一区别图形类型，系统保留到UserType

    def __init__(self, sourceNode, destNode):	#初始化信息为边的两个端点（这里的点应该是下面定义的Node类）
        super(Edge, self).__init__()	#调用父类初始化函数，参考：http://www.cnblogs.com/lovemo1314/archive/2011/05/03/2035005.html

        self.arrowSize = 6.0
        self.sourcePoint = QtCore.QPointF()	#QPointF：定义一个点
        self.destPoint = QtCore.QPointF()

        self.setAcceptedMouseButtons(QtCore.Qt.NoButton)	#设置这个图形不接受鼠标信息，而是传递到下层最近的接受鼠标信息的实例
        self.source = sourceNode
        self.dest = destNode
        self.source.addEdge(self)
        self.dest.addEdge(self)
        self.adjust()

    def type(self):	#重载：返回图形类型
        return Edge.Type

    def sourceNode(self):
        return self.source

    def setSourceNode(self, node):
        self.source = node
        self.adjust()

    def destNode(self):
        return self.dest

    def setDestNode(self, node):
        self.dest = node
        self.adjust()

    def adjust(self):
        if not self.source or not self.dest:
            return

        line = QtCore.QLineF(self.mapFromItem(self.source, 0, 0),
                self.mapFromItem(self.dest, 0, 0))
        #mapFromItem将  点(0, 0)从self.sourse的坐标系(其实就是sourse这个Node的坐标)  映射到self所在坐标系	
        #!! 这里是两个对象坐标系之间的转换
        length = line.length()

        self.prepareGeometryChange()	#改变形状之前调用来保证图形的矩形外界坐标正确

		#这里更新线段的位置#?? if干嘛用的??
        if length > 10.0:
            edgeOffset = QtCore.QPointF((line.dx() * 4) / length,
                    (line.dy() * 4) / length)

            self.sourcePoint = line.p1() + edgeOffset
            self.destPoint = line.p2() - edgeOffset
        else:
            self.sourcePoint = line.p1()
            self.destPoint = line.p1()

    def boundingRect(self):
        if not self.source or not self.dest:
            return QtCore.QRectF()

        penWidth = 1.0
        extra = (penWidth + self.arrowSize) / 2.0

        return QtCore.QRectF(self.sourcePoint,
                QtCore.QSizeF(self.destPoint.x() - self.sourcePoint.x(),
                        self.destPoint.y() - self.sourcePoint.y())).normalized().adjusted(-extra, -extra, extra, extra)

    def paint(self, painter, option, widget):
        if not self.source or not self.dest:
            return

        # Draw the line itself.
        line = QtCore.QLineF(self.sourcePoint, self.destPoint)

        if line.length() == 0.0:
            return

        painter.setPen(QtGui.QPen(QtCore.Qt.black, 1, QtCore.Qt.SolidLine,
                QtCore.Qt.RoundCap, QtCore.Qt.RoundJoin))
        painter.drawLine(line)

        # Draw the arrows if there's enough room.
        angle = math.acos(line.dx() / line.length())
        if line.dy() >= 0:
            angle = Edge.TwoPi - angle
			
        destArrowP1 = self.destPoint + QtCore.QPointF(math.sin(angle - Edge.Pi / 3) * self.arrowSize,
                                                      math.cos(angle - Edge.Pi / 3) * self.arrowSize)
        destArrowP2 = self.destPoint + QtCore.QPointF(math.sin(angle - Edge.Pi + Edge.Pi / 3) * self.arrowSize,
                                                      math.cos(angle - Edge.Pi + Edge.Pi / 3) * self.arrowSize)

        painter.setBrush(QtCore.Qt.black)
        painter.drawPolygon(QtGui.QPolygonF([line.p2(), destArrowP1, destArrowP2]))


class Node(QtGui.QGraphicsItem):
    Type = QtGui.QGraphicsItem.UserType + 1

    def __init__(self, graphWidget, color='', mainWindow=None):
        super(Node, self).__init__()
        #数据成员
        self.data = {}
        #图形部分
        self.main_window = mainWindow
        self.graph = graphWidget
        self.edgeList = []
        self.newPos = QtCore.QPointF()
        self.color = color
        self.init_color = color
        self.active_color = QtCore.Qt.cyan

        self.setFlag(QtGui.QGraphicsItem.ItemIsMovable)	#需要设置,如果对象需要移动
        self.setFlag(QtGui.QGraphicsItem.ItemSendsGeometryChanges)	#需要设置,如果对象需要移动
        self.setCacheMode(QtGui.QGraphicsItem.DeviceCoordinateCache)
        self.setAcceptHoverEvents(True)
        self.setZValue(1)

    def type(self):
        return Node.Type

    def addEdge(self, edge):
        self.edgeList.append(edge)
        edge.adjust()

    def edges(self):
        return self.edgeList

    #计算排斥力,防止两个点距离太近或完全重合
    def calculateForces(self):
        if not self.scene() or self.scene().mouseGrabberItem() is self:
            self.newPos = self.pos()
            return
    
        # Sum up all forces pushing this item away.
        xvel = 0.0
        yvel = 0.0
        for item in self.scene().items():	#遍历所在场景中的所有元素
            if not isinstance(item, Node):	#只考虑其中的节点(不考虑边)
                continue

            line = QtCore.QLineF(self.mapFromItem(item, 0, 0),
                    QtCore.QPointF(0, 0))	#注意这里为了体现为排斥的力,计算线段是从别的点指向自己的
            if line.length() < 5:	#只有两点距离近到25之内才开始排斥
                dx = line.dx()
                dy = line.dy()
                l = 2.0 * (dx * dx + dy * dy)
                if l > 0:
                    xvel += (dx * 50.0) / l
                    yvel += (dy * 50.0) / l
                    
            max_force = 3
            break_flag = 0
            if xvel>max_force:
                xvel = max_force
                #print '>>>>force is %d %d'%(xvel, yvel)
                break_flag = 1
            if xvel<-max_force:
                xvel = -max_force
                #print '>>>>force is %d %d'%(xvel, yvel)
                break_flag = 1
            if yvel>max_force:
                yvel = max_force
                #print '>>>>force is %d %d'%(xvel, yvel)
                break_flag = 1
            if yvel<-max_force:
                yvel = -max_force
                #print '>>>>force is %d %d'%(xvel, yvel)
                break_flag = 1
            if break_flag == 1:
                break

		#如果作用力很小,就认为没有
        if QtCore.qAbs(xvel) < 0.1 and QtCore.qAbs(yvel) < 0.1:
            xvel = yvel = 0.0

        sceneRect = self.scene().sceneRect()
        self.newPos = self.pos() + QtCore.QPointF(xvel, yvel)
        self.newPos.setX(min(max(self.newPos.x(), sceneRect.left() + 10), sceneRect.right() - 10))	#确保节点保持在场景内
        self.newPos.setY(min(max(self.newPos.y(), sceneRect.top() + 10), sceneRect.bottom() - 10))

    def advance(self):	#根据newPos更新节点位置
        if self.newPos == self.pos():
            return False

        self.setPos(self.newPos)
        return True

    def boundingRect(self):
        adjust = 2.0
        return QtCore.QRectF(-5 - adjust, -5 - adjust, 12 + adjust,
                12 + adjust)

    def shape(self):
        path = QtGui.QPainterPath()
        path.addEllipse(-5, -5, 10, 10)
        return path

    def paint(self, painter, option, widget):
        painter.setPen(QtCore.Qt.NoPen)

        if self.color=='':
            col = QtCore.Qt.gray
        elif self.color=='yellow':
            col = QtCore.Qt.yellow
        elif self.color=='green':
            col = QtCore.Qt.green
        elif self.color=='blue':
            col = QtCore.Qt.blue
        elif self.color=='cyan':
            col = QtCore.Qt.cyan
        else:
            col = self.color
		
        painter.setBrush(col)
        painter.setPen(QtGui.QPen(QtCore.Qt.black, 0))
        painter.drawEllipse(-5, -5, 10, 10)
		
    def changeColor(self, color):
        self.color=color
        self.update()
       
    def setInitColor(self, color):
        self.init_color = color
        self.changeColor(self.init_color)

    def itemChange(self, change, value):
        if change == QtGui.QGraphicsItem.ItemPositionHasChanged:
            for edge in self.edgeList:
                edge.adjust()
            self.graph.itemMoved()

        return super(Node, self).itemChange(change, value)

    @pyqtSignature("")
    def mousePressEvent(self, event):
        self.update()
        self.main_window.infoViewer.setText(self.content(True))
        super(Node, self).mousePressEvent(event)
    
    @pyqtSignature("")
    def mouseReleaseEvent(self, event):
        self.update()
        super(Node, self).mouseReleaseEvent(event)

    @pyqtSignature("")
    def hoverEnterEvent(self, event):
        self.activate()
        
    @pyqtSignature("")
    def hoverLeaveEvent(self, event):
        self.deActivate()
        
    def activate(self):
        self.changeColor(self.active_color)
        # calculate the position on desktop
        QtGui.QToolTip.showText(QtCore.QPoint(self.graph.mainWindow.x()+self.graph.x()+(self.x()+20)/(__builtin__.__dict__['Scene_width']+40)*self.graph.width(), self.graph.mainWindow.y()+self.graph.y()+(self.y()+20)/__builtin__.__dict__['Scene_height']*self.graph.height()), _fromUtf8(self.content()))
            
    # text that will show in tooltip, namely ip, id, port, nodes...
    def setSelfDate(self, key, value):
        print "key=%s, value=%s\n" % (key, value)
        self.data[key] = value
        
    def deActivate(self):
        self.changeColor(self.init_color)
        QtGui.QToolTip.hideText()
        
    def content(self, all=False):
        content = ''
        line_count = 0
        for item in self.data:
            if item in ['nodes', 'values', 'peers', 'results']:
                continue
            content += item+' : '+str(self.data[item])+'\n'
            line_count += 1 
        if 'nodes' in self.data:
            content += '\nnodes:\n'
            line_count += 1 
            node_count = 0
            for node in self.data['nodes']:
                node_count += 1
                content += '    '+str(node_count)+' : '+node['id']+'    '+node['ip']+'    '+str(node['port'])+'\n'
                line_count += 1 
        if 'values' in self.data:
            content += '\nvalues:\n'
            line_count += 1 
            value_count = 0
            for value in self.data['values']:
                value_count += 1
                content += '    '+str(value_count)+' : '+value['ip']+'   '+str(value['port'])+'\n'
                line_count += 1 
                if not all and line_count >= 16:
                    content += '    ......(click to see all)'
                    return content
        if 'peers' in self.data:
            content += '\npeers:\n'
            line_count += 1 
            peer_count = 0
            for peer in self.data['peers']:
                peer_count += 1
                content += '    '+str(peer_count)+' : '+peer['peer_id']+'    '+peer['ip']+'    '+str(peer['udp_port'])+'\n'
                line_count += 1 
        if 'results' in self.data:
            content += '\nvalues:\n'
            line_count += 1 
            result_count = 0
            for result in self.data['results']:
                result_count += 1
                content += "  [result %d/%d]\n" % (result_count, len(self.data['results']))
                content += "    kademlia hash:%s\n      tag list:\n" % (result['kademlia_hash'])
                line_count += 3
                tag_count = 0
                for tag in result['tags']:
                    tag_count += 1
                    content += "        tag[%d/%d]  %d  [%d] = %s\n" % (tag_count, len(result['tags']), tag['type'], tag['name'], tag['value'])
                    line_count += 1
                    if not all and line_count >= 16:
                        content += '    ......(click to see all)'
                        return content
            
        return content
        
        
        
class GraphWidget(QtGui.QGraphicsView):
    def __init__(self, parent=None):
        super(GraphWidget, self).__init__()
        
        self.mainWindow = parent

        self.timerId = 0

        scene = QtGui.QGraphicsScene(self)
        scene.setItemIndexMethod(QtGui.QGraphicsScene.NoIndex)
        scene.setSceneRect(0, 0, __builtin__.__dict__['Scene_width'], __builtin__.__dict__['Scene_height'])
        self.setScene(scene)
        self.setCacheMode(QtGui.QGraphicsView.CacheBackground)
        self.setViewportUpdateMode(QtGui.QGraphicsView.BoundingRectViewportUpdate)
        self.setRenderHint(QtGui.QPainter.Antialiasing)
        self.setTransformationAnchor(QtGui.QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QtGui.QGraphicsView.NoAnchor)
        self.setMouseTracking(True)
        
        #tip show
        self.tipWindow = QWidget(self)
        self.layout = QGridLayout(self.tipWindow)
        self.tipLabel = QLabel()
        self.layout.addWidget(self.tipLabel)
        

        #self.setMinimumSize(200, 200)

    def itemMoved(self):
        if not self.timerId:
            self.timerId = self.startTimer(1000 / 25)
            self.timerCount = 0

	#这个函数注释掉也没有影响,什么用??
    def keyPressEvent(self, event):
        key = event.key()

        if key == QtCore.Qt.Key_Up:
            self.centerNode.moveBy(0, -20)
        elif key == QtCore.Qt.Key_Down:
            self.centerNode.moveBy(0, 20)
        elif key == QtCore.Qt.Key_Left:
            self.centerNode.moveBy(-20, 0)
        elif key == QtCore.Qt.Key_Right:
            self.centerNode.moveBy(20, 0)
        elif key == QtCore.Qt.Key_Plus:
            self.scaleView(1.2)
        elif key == QtCore.Qt.Key_Minus:
            self.scaleView(1 / 1.2)
        elif key == QtCore.Qt.Key_Space or key == QtCore.Qt.Key_Enter:
            for item in self.scene().items():
                if isinstance(item, Node):
                    item.setPos(-150 + QtCore.qrand() % 300, -150 + QtCore.qrand() % 300)
        else:
            super(GraphWidget, self).keyPressEvent(event)

    def timerEvent(self, event):
        nodes = [item for item in self.scene().items() if isinstance(item, Node)]

        for node in nodes:
            node.calculateForces()

        itemsMoved = False
        #print 'timer started and there\'re %d nodes' % len(nodes)
        for node in nodes:
            if node.advance():
                itemsMoved = True

        self.timerCount += 1
        if self.timerCount >= 15 or not itemsMoved:
            self.killTimer(self.timerId)
            self.timerId = 0
            
    # def resizeEvent(self, event):
        # self.fitInView(self.scene().sceneRect(), 0)

    def wheelEvent(self, event):
        self.scaleView(math.pow(2.0, -event.delta() / 240.0))
        
    def drawBackground(self, painter, rect):
        # Shadow.
        sceneRect = self.sceneRect()

        # Fill.
        # gradient = QtGui.QLinearGradient(sceneRect.topLeft(),
                # sceneRect.bottomRight())
        # gradient.setColorAt(0, QtCore.Qt.white)
        # gradient.setColorAt(1, QtCore.Qt.lightGray)
        # painter.fillRect(rect.intersect(sceneRect), QtGui.QBrush(gradient))
        # painter.setBrush(QtCore.Qt.NoBrush)
        # painter.drawRect(sceneRect)

        # Text.
        textRect = QtCore.QRectF(sceneRect.left() + 4, sceneRect.top() + 4,
                sceneRect.width() - 4, sceneRect.height() - 4)

        font = painter.font()
        font.setBold(True)
        font.setPointSize(10)
        painter.setFont(font)
        painter.setPen(QtCore.Qt.black)
        painter.drawText(textRect.translated(__builtin__.__dict__['Scene_width']-50, __builtin__.__dict__['Scene_height']-25), _fromUtf8("时间(s)"))
        painter.drawText(textRect.translated(10, 10), _fromUtf8("距离(log)"))
		
        self.scene().addLine(5, __builtin__.__dict__['Scene_height']-5, __builtin__.__dict__['Scene_width'], __builtin__.__dict__['Scene_height']-5)
        self.scene().addLine(5, __builtin__.__dict__['Scene_height']-5, 5, 5)

    def scaleView(self, scaleFactor):
        factor = self.matrix().scale(scaleFactor, scaleFactor).mapRect(QtCore.QRectF(0, 0, 1, 1)).width()

        if factor < 0.07 or factor > 100:
            return

        self.scale(scaleFactor, scaleFactor)


if __name__ == '__main__':

    import sys

    app = QtGui.QApplication(sys.argv)
    QtCore.qsrand(QtCore.QTime(0,0,0).secsTo(QtCore.QTime.currentTime()))

    widget = GraphWidget()
    widget.show()

    sys.exit(app.exec_())
