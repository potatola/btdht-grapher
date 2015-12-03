## emuleKad graph
基于wireshark记录文件的，emuleKad搜包过程图形化实现。

功能：
	从Wireshark软件捕获的bt-dht trace文件中提取bt-dht的搜索和发布过程，并仿照eMule客户端的方式对这些过程进行图形化展示和细节信息（节点ID、IP、端口、客户端类型与版本；节点与目标的距离；节点对路由搜索请求的应答情况；节点与前驱节点的连接关系）的展示，帮助我们对bt-dht的路由和搜索/发布过程进行分析。
	
输入：
	用wireshark检测btdht查找过程时记录并保存的 pcap 类型文件。
	
输出：
	输入文件中涉及到的所有 btdht 查找过程，以及相应过程的图形化表示。
	
使用方法：
	1. 从 main.pyw 启动
	2. 见图片 description.jpg
	
运行环境：
	Windows 7 (X64)
	python 2.7
	PyQt GPL v4.9.1 for Python v2.7 (x64)