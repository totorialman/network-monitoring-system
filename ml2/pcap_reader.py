"""
Модуль для потокового чтения pcap/pcapng файлов.

Поддерживает чтение больших файлов (100+ ГБ) без загрузки в память —
пакеты обрабатываются по одному через callback-функцию.
"""

import os
import time
from typing import Dict, Optional, Callable, List
from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP, Dot1Q
from scapy.layers.inet6 import IPv6


class PcapFileReader:
    """
    Потоковый читатель pcap/pcapng файлов.
    
    Читает пакеты по одному, не загружая весь файл в память.
    Подходит для файлов размером 100+ ГБ.
    """
    
    def __init__(self, filepath: str):
        """
        Инициализация читателя pcap файла.
        
        Args:
            filepath: Путь к pcap или pcapng файлу
        """
        self.filepath = filepath
        self._validate_file()
    
    def _validate_file(self):
        """Проверка существования и доступности файла."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Файл {self.filepath} не найден")
        
        if not os.path.isfile(self.filepath):
            raise ValueError(f"{self.filepath} не является файлом")
        
        # Проверка расширения
        allowed_extensions = ('.pcap', '.pcapng', '.cap')
        _, ext = os.path.splitext(self.filepath)
        if ext.lower() not in allowed_extensions:
            raise ValueError(
                f"Неподдерживаемый формат файла: {ext}. "
                f"Ожидаются: {', '.join(allowed_extensions)}"
            )
    
    def get_file_size_gb(self) -> float:
        """Возвращает размер файла в ГБ."""
        return os.path.getsize(self.filepath) / (1024 ** 3)
    
    def extract_features(self, packet) -> Optional[Dict]:
        """
        Извлечение признаков из пакета (аналогично PacketCapture.extract_features).
        
        Args:
            packet: Scapy пакет
        
        Returns:
            Словарь с признаками или None если пакет не подходит
        """
        # Используем timestamp из pcap файла, если доступен
        packet_time = float(packet.time) if hasattr(packet, 'time') else time.time()
        
        features = {
            'timestamp': packet_time,
            'src_mac': None,
            'dst_mac': None,
            'vlan': None,
            'eth_type': None,
            'src_ip': None,
            'dst_ip': None,
            'icmp_type': None,
            'icmp_code': None,
            'proto': None,
            'ttl': None,
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'length': len(packet)
        }
        
        # Ethernet layer
        if Ether in packet:
            eth = packet[Ether]
            features['src_mac'] = eth.src
            features['dst_mac'] = eth.dst
            features['eth_type'] = hex(eth.type)
            
            # VLAN
            if Dot1Q in packet:
                features['vlan'] = packet[Dot1Q].vlan
        
        # IP layer (IPv4)
        if IP in packet:
            ip = packet[IP]
            features['src_ip'] = ip.src
            features['dst_ip'] = ip.dst
            features['proto'] = ip.proto
            features['ttl'] = ip.ttl
            
            # TCP
            if TCP in packet:
                tcp = packet[TCP]
                features['src_port'] = tcp.sport
                features['dst_port'] = tcp.dport
                features['tcp_flags'] = int(tcp.flags)
            
            # UDP
            elif UDP in packet:
                udp = packet[UDP]
                features['src_port'] = udp.sport
                features['dst_port'] = udp.dport
            
            # ICMP
            elif ICMP in packet:
                icmp = packet[ICMP]
                features['icmp_type'] = icmp.type
                features['icmp_code'] = icmp.code
        
        # IPv6
        elif IPv6 in packet:
            ipv6 = packet[IPv6]
            features['src_ip'] = ipv6.src
            features['dst_ip'] = ipv6.dst
            features['proto'] = ipv6.nh
            features['ttl'] = ipv6.hlim
            
            if TCP in packet:
                tcp = packet[TCP]
                features['src_port'] = tcp.sport
                features['dst_port'] = tcp.dport
                features['tcp_flags'] = int(tcp.flags)
            elif UDP in packet:
                udp = packet[UDP]
                features['src_port'] = udp.sport
                features['dst_port'] = udp.dport
            elif ICMP in packet:
                icmp = packet[ICMP]
                features['icmp_type'] = icmp.type
                features['icmp_code'] = icmp.code
        
        # ARP
        elif ARP in packet:
            arp = packet[ARP]
            features['src_ip'] = arp.psrc
            features['dst_ip'] = arp.pdst
        
        return features
    
    def read_packets(
        self,
        callback: Callable[[Dict], None],
        max_packets: Optional[int] = None,
        progress_interval: int = 100000
    ) -> int:
        """
        Потоковое чтение пакетов из pcap файла.
        
        Пакеты читаются по одному и передаются в callback-функцию.
        Весь файл НЕ загружается в память.
        
        Args:
            callback: Функция, вызываемая для каждого обработанного пакета.
                      Принимает словарь с признаками пакета.
            max_packets: Максимальное количество пакетов для чтения (None = все)
            progress_interval: Выводить прогресс каждые N пакетов
        
        Returns:
            Общее количество обработанных пакетов
        """
        file_size_gb = self.get_file_size_gb()
        print(f"Открытие pcap файла: {self.filepath}")
        print(f"Размер файла: {file_size_gb:.2f} ГБ")
        print(f"Начало потокового чтения...")
        print()
        
        total_packets = 0
        processed_packets = 0
        skipped_packets = 0
        start_time = time.time()
        last_progress_time = start_time
        
        try:
            # PcapReader читает пакеты лениво, по одному
            with PcapReader(self.filepath) as pcap_reader:
                for packet in pcap_reader:
                    total_packets += 1
                    
                    # Извлекаем признаки
                    features = self.extract_features(packet)
                    
                    if features:
                        callback(features)
                        processed_packets += 1
                    else:
                        skipped_packets += 1
                    
                    # Проверка лимита пакетов
                    if max_packets and processed_packets >= max_packets:
                        print(f"\nДостигнут лимит: {max_packets} пакетов")
                        break
                    
                    # Вывод прогресса
                    if total_packets % progress_interval == 0:
                        elapsed = time.time() - start_time
                        rate = total_packets / elapsed if elapsed > 0 else 0
                        print(
                            f"Прогресс: {total_packets:,} пакетов прочитано, "
                            f"{processed_packets:,} обработано, "
                            f"{skipped_packets:,} пропущено | "
                            f"Скорость: {rate:,.0f} pkt/s | "
                            f"Время: {elapsed:.0f}s"
                        )
        
        except EOFError:
            print("\nДостигнут конец pcap файла")
        except Exception as e:
            print(f"\nОшибка при чтении pcap файла: {e}")
            raise
        
        elapsed = time.time() - start_time
        print()
        print(f"=" * 60)
        print(f"Чтение pcap файла завершено")
        print(f"Всего пакетов в файле: {total_packets:,}")
        print(f"Обработано пакетов: {processed_packets:,}")
        print(f"Пропущено пакетов: {skipped_packets:,}")
        print(f"Время обработки: {elapsed:.2f} секунд")
        if elapsed > 0:
            print(f"Средняя скорость: {total_packets / elapsed:,.0f} пакетов/сек")
        print(f"=" * 60)
        
        return processed_packets