import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QComboBox, QMessageBox, QTreeView, QTextEdit, QScrollArea
from PyQt5.QtCore import  QThread, pyqtSignal
from scapy.all import get_working_ifaces, AsyncSniffer, Padding, Raw  # 显式导入Padding和Raw
from scapy.arch import compile_filter
from scapy.layers.http import *  # 如果使用HTTP相关层，则需要单独导入
from datetime import datetime
from queue import Queue


class PacketAnalyzer(QThread):
    packet_analyzed = pyqtSignal(dict)

    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def determine_protocol(self, packet):
        if 'IP' in packet:
            ip_layer = packet['IP']
            if 'TCP' in ip_layer:
                return 'TCP'
            elif 'UDP' in ip_layer:
                return 'UDP'
            elif 'ICMP' in ip_layer:
                return 'ICMP'
        elif 'IPv6' in packet:
            ipv6_layer = packet['IPv6']
            if 'TCP' in ipv6_layer:
                return 'TCP'
            elif 'UDP' in ipv6_layer:
                return 'UDP'
            elif 'ICMPv6' in ipv6_layer:
                return 'ICMPv6'

        # 遍历所有层，寻找有效层
        layer = next((l for l in packet.layers() if not isinstance(l, (Padding, Raw))), None)
        if layer is not None:
            layer_name = str(getattr(layer, 'name', 'Unknown'))
            if layer_name in ('DNSQR', 'DNSRR'):
                return 'DNS'
            else:
                return layer_name

        return 'Unknown'

    def run(self):
        while True:
            index, packet = self.queue.get()
            # 打印packet的摘要信息
            # print(packet.summary())

            packet_time = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')

            if 'IP' in packet:
                src = packet['IP'].src
                dst = packet['IP'].dst
            elif 'IPv6' in packet:
                src = packet['IPv6'].src
                dst = packet['IPv6'].dst
            else:
                src = packet.src
                dst = packet.dst

            protocol = self.determine_protocol(packet)

            length = str(len(packet))
            try:
                info = packet.summary()
            except:
                info = 'Unknown info format'

            # 获取端口信息
            src_port = ''
            dst_port = ''
            if 'TCP' in packet or 'UDP' in packet:
                src_port = packet['TCP'].sport if 'TCP' in packet else packet['UDP'].sport
                dst_port = packet['TCP'].dport if 'TCP' in packet else packet['UDP'].dport

            self.packet_analyzed.emit({
                'time': packet_time,
                'src': src,
                'dst': dst,
                'src_port': str(src_port),
                'dst_port': str(dst_port),
                'protocol': protocol,
                'length': length,
                'info': info
            })
class SnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Sniffer')
        self.setGeometry(100, 100, 2560, 1440)

        self.iface = ''
        self.packets = []
        self.handling_q = Queue()
        self.working = False
        self.filter_content = ''
        self.packet_nums = 0
        self.interfaces = []

        self.initUI()

    def initUI(self):
        central_widget = QWidget()
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # 网络接口选择
        self.interface_label = QLabel('选择网络接口:')
        layout.addWidget(self.interface_label)

        self.interface_combobox = QComboBox()
        self.interfaces = get_working_ifaces()
        for iface in self.interfaces:
            self.interface_combobox.addItem(iface.name)
        self.interface_combobox.currentTextChanged.connect(self.select_interface)
        layout.addWidget(self.interface_combobox)

        self.start_button = QPushButton('开始抓包', self)
        self.start_button.clicked.connect(self.toggle_sniffing)
        layout.addWidget(self.start_button)

        self.filter_label = QLabel('输入捕获过滤器:')
        layout.addWidget(self.filter_label)

        self.filter_entry = QLineEdit()
        self.filter_entry.editingFinished.connect(self.check_filter)
        layout.addWidget(self.filter_entry)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        self.packet_table.setColumnWidth(0, 300)  # 设置第一列宽度为 300 像素
        self.packet_table.setColumnWidth(1, 200)  # 设置第二列宽度为 200 像素
        self.packet_table.setColumnWidth(2, 200)  # 设置第三列宽度为 200 像素
        self.packet_table.setColumnWidth(3, 150)  # 设置第四列宽度为 200 像素
        self.packet_table.setColumnWidth(4, 150)  # 设置第五列宽度为 200 像素
        self.packet_table.setColumnWidth(5, 100)  # 设置第六列宽度为 100 像素
        self.packet_table.setColumnWidth(6, 100)  # 设置第七列宽度为 1000 像素
        self.packet_table.setColumnWidth(7, 1000)  # 设置第八列宽度为 1000 像素
        self.packet_table.setHorizontalHeaderLabels(
            ['Time', 'Source', 'Destination', 'SrcPort', 'DstPort', 'Protocol', 'Length', 'Info'])
        layout.addWidget(self.packet_table)

        self.packet_analyzer_threads = []
        for _ in range(3):
            thread = PacketAnalyzer(self.handling_q)
            thread.packet_analyzed.connect(self.update_packet_table)
            thread.start()
            self.packet_analyzer_threads.append(thread)

    def select_interface(self, iface_name):
        self.iface = iface_name

    def toggle_sniffing(self):
        if self.working:
            self.sniffer.stop()
            self.start_button.setText('开始抓包')
            self.working = False
        else:
            if not self.iface:
                QMessageBox.warning(self, '警告', '请选择网络接口！')
                return
            self.packet_nums = 0
            self.packets.clear()
            self.packet_table.setRowCount(0)
            self.sniffer = AsyncSniffer(iface=self.iface, filter=self.filter_content, prn=self.packet_analyzed)
            self.sniffer.start()
            self.start_button.setText('停止抓包')
            self.working = True

    def packet_analyzed(self, packet):
        self.packets.append(packet)
        self.packet_nums += 1
        self.handling_q.put([self.packet_nums, packet])

    def check_filter(self):
        self.filter_content = self.filter_entry.text().strip()
        if self.filter_content == '':
            self.filter_entry.setStyleSheet("background-color: white;")
            return

        try:
            # 使用正则表达式简单检查过滤器格式
            if not re.match(r'^[\w\s\.,=\(\)\[\]\{\}\+\-\*\&\|\<\>\!\:\;\/\\]+$', self.filter_content):
                raise ValueError("Invalid characters in the filter")

            # 尝试使用 Scapy 编译过滤器
            compiled_filter = compile_filter(self.filter_content)
            self.filter_entry.setStyleSheet("background-color: green;")
        except Exception as e:
            print(f"Filter error: {e}")
            self.filter_entry.setStyleSheet("background-color: red;")
            self.filter_content = ''

    def update_packet_table(self, data):
        row_count = self.packet_table.rowCount()
        self.packet_table.insertRow(row_count)
        self.packet_table.setItem(row_count, 0, QTableWidgetItem(data['time']))
        self.packet_table.setItem(row_count, 1, QTableWidgetItem(data['src']))
        self.packet_table.setItem(row_count, 2, QTableWidgetItem(data['dst']))
        self.packet_table.setItem(row_count, 3, QTableWidgetItem(data['src_port']))
        self.packet_table.setItem(row_count, 4, QTableWidgetItem(data['dst_port']))
        self.packet_table.setItem(row_count, 5, QTableWidgetItem(data['protocol']))
        self.packet_table.setItem(row_count, 6, QTableWidgetItem(data['length']))
        self.packet_table.setItem(row_count, 7, QTableWidgetItem(data['info']))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = SnifferGUI()
    gui.show()
    sys.exit(app.exec_())