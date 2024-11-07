import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QLabel, QLineEdit, QComboBox, QMessageBox, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import get_working_ifaces, AsyncSniffer, Padding, Raw
from scapy.arch import compile_filter
from scapy.layers.http import *
from datetime import datetime
from queue import Queue
import binascii  # 用于将二进制数据转换为十六进制字符串


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

        layer = next((l for l in packet.layers() if not isinstance(l, (Padding, Raw))), None)
        if layer is not None:
            layer_name = str(getattr(layer, 'name', 'Unknown'))
            if layer_name in ('DNSQR', 'DNSRR'):
                return 'DNS'
            else:
                return layer_name

        return 'Unknown'

    def parse_packet(self, packet):
        packet_info = {
            'time': datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
            'src': packet['IP'].src if 'IP' in packet else packet.src,
            'dst': packet['IP'].dst if 'IP' in packet else packet.dst,
            'src_port': '',
            'dst_port': '',
            'protocol': self.determine_protocol(packet),
            'length': str(len(packet)),
            'info': packet.summary(),
            'binary_data': binascii.hexlify(bytes(packet)).decode('utf-8')
        }

        if 'TCP' in packet or 'UDP' in packet:
            packet_info['src_port'] = packet['TCP'].sport if 'TCP' in packet else packet['UDP'].sport
            packet_info['dst_port'] = packet['TCP'].dport if 'TCP' in packet else packet['UDP'].dport

        return packet_info

    def run(self):
        while True:
            index, packet = self.queue.get()
            packet_info = self.parse_packet(packet)
            self.packet_analyzed.emit(packet_info)


class SnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Sniffer')
        self.setGeometry(100, 100, 2560, 1440)

        self.iface = ''  # 默认值将在这里设置
        self.packets = []
        self.handling_q = Queue()
        self.working = False
        self.filter_content = ''
        self.packet_nums = 0
        self.interfaces = []

        # 获取可用的网络接口列表
        self.interfaces = get_working_ifaces()
        if self.interfaces:
            self.iface = self.interfaces[0].name  # 设置默认网络接口为第一个可用接口

        self.initUI()

    def initUI(self):
        central_widget = QWidget()
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # 网络接口选择
        self.interface_label = QLabel('选择网络接口:')
        layout.addWidget(self.interface_label)

        # 初始化下拉框并设置默认值
        self.interface_combobox = QComboBox()
        for iface in self.interfaces:
            self.interface_combobox.addItem(iface.name)
        self.interface_combobox.setCurrentText(self.iface)  # 设置默认值
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
        self.packet_table.setColumnCount(9)  # 增加一列
        self.packet_table.setColumnWidth(0, 300)  # 设置第一列宽度为 300 像素
        self.packet_table.setColumnWidth(1, 200)  # 设置第二列宽度为 200 像素
        self.packet_table.setColumnWidth(2, 200)  # 设置第三列宽度为 200 像素
        self.packet_table.setColumnWidth(3, 200)  # 设置第四列宽度为 200 像素
        self.packet_table.setColumnWidth(4, 200)  # 设置第五列宽度为 200 像素
        self.packet_table.setColumnWidth(5, 100)  # 设置第六列宽度为 100 像素
        self.packet_table.setColumnWidth(6, 100)  # 设置第七列宽度为 100 像素
        self.packet_table.setColumnWidth(7, 1000)  # 设置第八列宽度为 1000 像素
        self.packet_table.setColumnWidth(8, 1000)  # 设置第九列宽度为 1000 像素
        self.packet_table.setHorizontalHeaderLabels(
            ['Time', 'Source', 'Destination', 'SrcPort', 'DstPort', 'Protocol', 'Length', 'Info', 'Binary Data'])
        self.packet_table.cellClicked.connect(self.show_packet_details)
        layout.addWidget(self.packet_table)

        # 添加一个文本区域来显示解析结果
        self.packet_details = QTextEdit()
        layout.addWidget(self.packet_details)

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
            if not re.match(r'^[\w\s\.,=\(\)\[\]\{\}\+\-\*\&\|\<\>\!\:\;\/\\]+$', self.filter_content):
                raise ValueError("Invalid characters in the filter")

            compile_filter(self.filter_content)
            self.filter_entry.setStyleSheet("background-color: green;")
        except Exception as e:
            print(f"Filter error: {e}")
            self.filter_entry.setStyleSheet("background-color: red;")
            self.filter_content = ''
            QMessageBox.critical(
                self,
                '错误',
                f'输入的过滤器格式有误：{str(e)}\n\n'
                '正确的过滤器格式示例：\n'
                '- 只捕获特定的IP地址: host 192.168.1.1\n'
                '- 捕获特定端口上的流量: port 80\n'
                '- 捕获特定协议的流量: tcp or udp or icmp'
            )

    def update_packet_table(self, data):
        row_count = self.packet_table.rowCount()
        self.packet_table.insertRow(row_count)
        self.packet_table.setItem(row_count, 0, QTableWidgetItem(data['time']))
        self.packet_table.setItem(row_count, 1, QTableWidgetItem(data['src']))
        self.packet_table.setItem(row_count, 2, QTableWidgetItem(data['dst']))
        self.packet_table.setItem(row_count, 3, QTableWidgetItem(str(data['src_port'])))
        self.packet_table.setItem(row_count, 4, QTableWidgetItem(str(data['dst_port'])))
        self.packet_table.setItem(row_count, 5, QTableWidgetItem(data['protocol']))
        self.packet_table.setItem(row_count, 6, QTableWidgetItem(data['length']))
        self.packet_table.setItem(row_count, 7, QTableWidgetItem(data['info']))
        self.packet_table.setItem(row_count, 8, QTableWidgetItem(data['binary_data']))

    def show_packet_details(self, row, column):
        data = {
            'time': self.packet_table.item(row, 0).text(),
            'src': self.packet_table.item(row, 1).text(),
            'dst': self.packet_table.item(row, 2).text(),
            'src_port': self.packet_table.item(row, 3).text(),
            'dst_port': self.packet_table.item(row, 4).text(),
            'protocol': self.packet_table.item(row, 5).text(),
            'length': self.packet_table.item(row, 6).text(),
            'info': self.packet_table.item(row, 7).text(),
            'binary_data': self.packet_table.item(row, 8).text()
        }
        details = (
            f"Time: {data['time']}\n"
            f"Source: {data['src']}\n"
            f"Destination: {data['dst']}\n"
            f"Source Port: {data['src_port']}\n"
            f"Destination Port: {data['dst_port']}\n"
            f"Protocol: {data['protocol']}\n"
            f"Length: {data['length']}\n"
            f"Info: {data['info']}\n"
            f"Binary Data: {data['binary_data']}\n"
            f"\n"
            f"解析结果:\n"
            f"----------------------------------------\n"
        )

        # 解析二进制数据
        hex_data = data['binary_data']
        parsed_data = self.parse_hex_data(hex_data)
        details += parsed_data

        self.packet_details.setPlainText(details)

    def parse_hex_data(self, hex_data):
        parsed_data = ""
        # 解析以太网头部
        eth_header = hex_data[:24]
        parsed_data += f"以太网头部: {eth_header}\n"

        # 解析IP头部
        ip_header = hex_data[24:60]
        parsed_data += f"IP头部: {ip_header}\n"
        version = int(ip_header[0], 16) >> 4
        header_length = (int(ip_header[0], 16) & 0x0F) * 4
        tos = int(ip_header[1:3], 16)
        total_length = int(ip_header[3:7], 16)
        identification = int(ip_header[7:11], 16)
        flags = int(ip_header[11:12], 16) >> 5
        fragment_offset = int(ip_header[11:15], 16) & 0x1FFF
        ttl = int(ip_header[15:17], 16)
        protocol = int(ip_header[17:19], 16)
        header_checksum = int(ip_header[19:23], 16)
        src_ip = '.'.join([str(int(ip_header[i:i+2], 16)) for i in range(24, 32, 2)])
        dst_ip = '.'.join([str(int(ip_header[32:40], 16)) for i in range(40, 48, 2)])

        parsed_data += f"  版本: {version}\n"
        parsed_data += f"  头部长度: {header_length} 字节\n"
        parsed_data += f"  服务类型: {tos}\n"
        parsed_data += f"  总长度: {total_length} 字节\n"
        parsed_data += f"  标识: {identification}\n"
        parsed_data += f"  标志: {flags}\n"
        parsed_data += f"  片偏移: {fragment_offset}\n"
        parsed_data += f"  生存时间: {ttl}\n"
        parsed_data += f"  协议: {protocol}\n"
        parsed_data += f"  头部校验和: {header_checksum}\n"
        parsed_data += f"  源IP: {src_ip}\n"
        parsed_data += f"  目的IP: {dst_ip}\n"

        # 解析TCP头部
        if protocol == 6:
            tcp_header = hex_data[60:100]
            parsed_data += f"TCP头部: {tcp_header}\n"
            src_port = int(tcp_header[0:4], 16)
            dst_port = int(tcp_header[4:8], 16)
            sequence_number = int(tcp_header[8:16], 16)
            acknowledgment_number = int(tcp_header[16:24], 16)
            data_offset = (int(tcp_header[24], 16) >> 4) * 4
            flags = int(tcp_header[26:28], 16)
            window_size = int(tcp_header[28:32], 16)
            checksum = int(tcp_header[32:36], 16)
            urgent_pointer = int(tcp_header[36:40], 16)

            parsed_data += f"  源端口: {src_port}\n"
            parsed_data += f"  目的端口: {dst_port}\n"
            parsed_data += f"  序列号: {sequence_number}\n"
            parsed_data += f"  确认号: {acknowledgment_number}\n"
            parsed_data += f"  数据偏移: {data_offset} 字节\n"
            parsed_data += f"  标志: {flags}\n"
            parsed_data += f"  窗口大小: {window_size}\n"
            parsed_data += f"  校验和: {checksum}\n"
            parsed_data += f"  紧急指针: {urgent_pointer}\n"

        # 解析数据部分
        data_start = 100
        data_end = len(hex_data)
        data = hex_data[data_start:data_end]
        parsed_data += f"数据: {data}\n"

        return parsed_data


if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = SnifferGUI()
    gui.show()
    sys.exit(app.exec_())