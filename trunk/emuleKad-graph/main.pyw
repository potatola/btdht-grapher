from PyQt4.QtCore import *
from PyQt4.QtGui import *
from ui_mainGui1 import *
from nodeView import *
from dispach import *
from Packet_bencode import *
from Packet_eDonkey import *
import traceback
import socket
import sys
import thread
import __builtin__
try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s
MAC = "qt_mac_set_native_menubar" in dir()

class Main(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(Main, self).__init__(parent)
        self.setupUi(self)
        #添加图形显示的画布
        self.Nodes = GraphWidget(self)
        self.verticalLayout_3.insertWidget(2, self.Nodes)
        
        # the searching targets list table
        # self.List = QTableWidget(0, 3, self)
        self.ListCount = 0
        self.List.setColumnCount(3)
        self.List.setHorizontalHeaderLabels(['ID', _fromUtf8('类型'), _fromUtf8('距离(/160)')])
        self.List.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.List.setSelectionBehavior(QAbstractItemView.SelectRows)
        # self.verticalLayout_2.insertWidget(2, self.List)
        # self.List.setSizePolicy (QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Expanding)
        self.List.setMinimumHeight(160)
        self.List.setColumnWidth(0, 300)
        
        # self.List.insertRow(self.ListCount)
        # self.ListCount += 1
        # newItem = QTableWidgetItem("60g")
        # self.List.setItem(self.ListCount-1, 2, newItem)
        
        self.IPLineEdit.setText(socket.gethostbyname_ex(socket.gethostname())[2][0])
        
        #限制文本框的输入内容
        regExp1 = QRegExp("[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}");
        pRegExpValidator1 = QRegExpValidator(regExp1, self);
        self.IPLineEdit.setValidator(pRegExpValidator1);
        regExp2 = QRegExp("[0-9]{1,5}");
        pRegExpValidator2 = QRegExpValidator(regExp2, self);
        self.portLineEdit.setValidator(pRegExpValidator2);
        self.update()
        if not MAC:
            self.workButton.setFocusPolicy(Qt.NoFocus)
            self.traceButton.setFocusPolicy(Qt.NoFocus)
        self.updateUi()
        
    @pyqtSignature("QString")        
    def on_IPLineEdit_textEdited(self):
        self.updateUi()
    @pyqtSignature("QString")
    def on_portLineEdit_textEdited(self):
        self.updateUi()
    @pyqtSignature("QString")    
    def on_traceLineEdit_textEdited(self):
        self.updateUi()
        
    @pyqtSignature("")
    def on_traceButton_clicked(self):
        fileDir = QtGui.QFileDialog.getOpenFileName(self, "select trace file", QtCore.QDir.currentPath())
        self.traceLineEdit.setText(fileDir)
        self.updateUi()
        
    #find out all searching progresses
    @pyqtSignature("")
    def on_workButton_clicked(self):
    # extract all look-ups
        #reply = QMessageBox.question(self, 'message', _fromUtf8('开始工作'), QMessageBox.Yes, QMessageBox.No)
        #开始前的准备工作
        self.List.clear()
        self.List.setRowCount(0)
        self.ListCount = 0
        self.List.setColumnCount(3)
        self.List.setHorizontalHeaderLabels(['ID', _fromUtf8('类型'), _fromUtf8('距离(/160)')])
        trace = self.traceLineEdit.text()
        trace = unicode(trace.toUtf8(),'utf8', 'ignore').encode('gb2312')
        try:
            dispachor = Dispach(trace)
            analysor = Analyser(self.Nodes, self)
            dispachor.bencoder.analysing = analysor

            self.IPLineEdit.setText(dispachor.local_ip())
            dispachor.work()
        except:
            traceback.print_exc()
            QMessageBox.warning(self, _fromUtf8(str(sys.exc_info()[0])), _fromUtf8(str(sys.exc_info()[1])), QMessageBox.Yes)
            return
        
    @pyqtSignature("")
    def on_drawButton_clicked(self):
        selectedList = self.List.selectedItems()
        if len(selectedList) == 0:
            QMessageBox.warning(self, _fromUtf8('没有选择需要显示的内容!'), _fromUtf8('请先提取所有检索内容，然后在下方列表中选择一个需要显示的检索条目'),
            QMessageBox.Yes)
            return
        #print selectedList[0].text()
        
        trace = self.traceLineEdit.text()
        trace = unicode(trace.toUtf8(),'utf8', 'ignore').encode('gb2312')
        dispachor = Dispach(trace)
        analysor = Analyser(self.Nodes, self, 0)
        dispachor.bencoder.analysing = analysor
        
        dispachor.work(0)
        
    @pyqtSignature("QString")
    def on_timeScopeSpin_valueChanged(self):
        __builtin__.__dict__['IGNORE_TIME'] = self.timeScopeSpin.value()
        __builtin__.__dict__['Scene_width'] = __builtin__.__dict__['IGNORE_TIME'] * __builtin__.__dict__['Scene_time_multi']
        self.Nodes.scene().setSceneRect(0, 0, __builtin__.__dict__['Scene_width'], __builtin__.__dict__['Scene_height'])
        
    @pyqtSignature("QString")
    def on_timeMultiSpin_valueChanged(self):
        __builtin__.__dict__['Scene_time_multi'] = self.timeMultiSpin.value()
        __builtin__.__dict__['Scene_width'] = __builtin__.__dict__['IGNORE_TIME'] * __builtin__.__dict__['Scene_time_multi']
        self.Nodes.scene().setSceneRect(0, 0, __builtin__.__dict__['Scene_width'], __builtin__.__dict__['Scene_height'])
        
    def updateUi(self):
        enable = not (self.IPLineEdit.text().isEmpty() or self.traceLineEdit.text().isEmpty())
        self.workButton.setEnabled(enable)
        self.drawButton.setEnabled(enable)
            
if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    form = Main()
    
    form.show()
    app.exec_()
