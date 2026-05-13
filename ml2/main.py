#!/usr/bin/env python3
"""
Основной модуль для обучения модели и детекции аномалий в сетевом трафике.

Поддерживает два источника данных для обучения:
1. Захват трафика с сетевого интерфейса в реальном времени
2. Чтение из pcap/pcapng файла (потоковое, подходит для файлов 100+ ГБ)

Для больших дампов (100+ ГБ) поддерживается обучение на нескольких pcap-файлах:
  python main.py --mode train --pcap dump1.pcap --pcap dump2.pcap --model model.pkl
"""

import argparse
import sys
import os
from typing import List, Optional
from packet_capture import PacketCapture
from pcap_reader import PcapFileReader
from aggregation import TimeWindowAggregator
from anomaly_detector import AnomalyDetector
from alerting import TrafficLogger, build_zip_from_packets, send_zip_to_server
import config
import time


def _read_pcaps_into_aggregator(
    pcap_paths: List[str],
    aggregator: TimeWindowAggregator,
    max_packets_per_file: Optional[int] = None
) -> List[dict]:
    """
    Потоковое чтение одного или нескольких pcap-файлов в агрегатор.
    
    Пакеты читаются по одному через PcapFileReader, не загружая файлы в память.
    Все агрегированные окна из всех файлов собираются в единый список.
    
    Args:
        pcap_paths: Список путей к pcap/pcapng/cap файлам
        aggregator: Экземпляр TimeWindowAggregator для агрегации
        max_packets_per_file: Максимум пакетов из каждого файла (None = все)
    
    Returns:
        Список агрегированных окон (словарей признаков) из всех файлов
    """
    all_aggregated = []
    total_files = len(pcap_paths)

    for idx, pcap_path in enumerate(pcap_paths, start=1):
        print(f"\n{'=' * 60}")
        print(f"[{idx}/{total_files}] Обработка файла: {pcap_path}")
        print(f"{'=' * 60}")

        if not os.path.exists(pcap_path):
            print(f"Ошибка: pcap файл {pcap_path} не найден. Пропускаем.")
            continue

        reader = PcapFileReader(pcap_path)

        def process_packet(pkt):
            completed = aggregator.add_packet(pkt)
            all_aggregated.extend(completed)

        reader.read_packets(
            callback=process_packet,
            max_packets=max_packets_per_file,
            progress_interval=config.training.pcap_progress_interval
        )

        # Выводим промежуточную статистику
        print(f"  → Накоплено агрегированных окон: {len(all_aggregated)}")

    # Завершаем последние незакрытые окна
    remaining = aggregator.flush()
    all_aggregated.extend(remaining)

    return all_aggregated


def train_model_from_interface(interface: str, duration_minutes: int,
                                window_size: float, model_path: str):
    """
    Обучение модели на сетевом трафике с интерфейса.
    
    Args:
        interface: Имя сетевого интерфейса
        duration_minutes: Длительность обучения в минутах
        window_size: Размер временного окна в секундах
        model_path: Путь для сохранения модели
    """
    print(f"=" * 60)
    print(f"Обучение модели детекции аномалий (с интерфейса)")
    print(f"Интерфейс: {interface}")
    print(f"Длительность: {duration_minutes} минут")
    print(f"Размер окна: {window_size} секунд")
    print(f"=" * 60)
    
    # Инициализация компонентов
    capture = PacketCapture(interface)
    detector = AnomalyDetector(contamination=config.model.contamination)
    aggregator = TimeWindowAggregator(window_size=window_size)
    
    aggregated_data = []
    
    def process_packet(packet):
        """Обработка каждого захваченного пакета."""
        completed = aggregator.add_packet(packet)
        aggregated_data.extend(completed)
    
    # Захват пакетов
    duration_seconds = duration_minutes * 60
    capture.capture_packets(duration_seconds, callback=process_packet)
    
    # Завершение последних агрегированных данных
    remaining = aggregator.flush()
    aggregated_data.extend(remaining)
    
    if not aggregated_data:
        print("Ошибка: Не удалось собрать данные для обучения.")
        sys.exit(1)
    
    print(f"\nСобрано {len(aggregated_data)} агрегированных образцов")
    
    # Обучение модели
    try:
        detector.train(aggregated_data)
        detector.save(model_path)
        print(f"\nОбучение завершено успешно!")
    except Exception as e:
        print(f"Ошибка при обучении: {e}")
        sys.exit(1)


def train_model_from_pcaps(pcap_paths: List[str], window_size: float, model_path: str,
                            max_packets: Optional[int] = None):
    """
    Обучение модели на трафике из одного или нескольких pcap файлов (потоковое чтение).
    
    Подходит для больших файлов (100+ ГБ) — пакеты читаются по одному
    и не загружаются в память целиком. Несколько файлов обрабатываются
    последовательно, а агрегированные данные накапливаются для одного
    сеанса обучения модели.
    
    Args:
        pcap_paths: Список путей к pcap/pcapng файлам
        window_size: Размер временного окна в секундах
        model_path: Путь для сохранения модели
        max_packets: Максимальное количество пакетов на файл (None = все)
    """
    print(f"=" * 70)
    print(f"Обучение модели детекции аномалий (из pcap файлов)")
    print(f"Всего файлов: {len(pcap_paths)}")
    for p in pcap_paths:
        print(f"  - {p}")
    print(f"Размер окна: {window_size} секунд")
    if max_packets:
        print(f"Лимит пакетов на файл: {max_packets:,}")
    print(f"=" * 70)
    print()

    # Инициализация компонентов (один раз для всех файлов)
    detector = AnomalyDetector(contamination=config.model.contamination)
    aggregator = TimeWindowAggregator(window_size=window_size)

    # Потоковое чтение всех pcap файлов
    aggregated_data = _read_pcaps_into_aggregator(
        pcap_paths=pcap_paths,
        aggregator=aggregator,
        max_packets_per_file=max_packets
    )

    if not aggregated_data:
        print("Ошибка: Не удалось собрать данные для обучения из pcap файлов.")
        sys.exit(1)

    print(f"\nСобрано {len(aggregated_data)} агрегированных образцов из {len(pcap_paths)} pcap-файла(ов)")

    # Обучение модели (один раз на всех данных)
    try:
        detector.train(aggregated_data)
        detector.save(model_path)
        print(f"\nОбучение завершено успешно!")
        print(f"Модель сохранена в: {model_path}")
    except Exception as e:
        print(f"Ошибка при обучении: {e}")
        sys.exit(1)


# Для обратной совместимости — старый однофайловый вызов через новую функцию
def train_model_from_pcap(pcap_path: str, window_size: float, model_path: str,
                           max_packets: Optional[int] = None):
    """
    Обучение модели на трафике из одного pcap файла (потоковое чтение).
    
    Args:
        pcap_path: Путь к pcap/pcapng файлу
        window_size: Размер временного окна в секундах
        model_path: Путь для сохранения модели
        max_packets: Максимальное количество пакетов для обработки (None = все)
    """
    train_model_from_pcaps(
        pcap_paths=[pcap_path],
        window_size=window_size,
        model_path=model_path,
        max_packets=max_packets
    )


def detect_anomalies(interface: str, model_path: str,
                     window_size: float, score_threshold: Optional[float] = None):
    """
    Детекция аномалий в реальном времени.
    
    Args:
        interface: Имя сетевого интерфейса
        model_path: Путь к сохраненной модели
        window_size: Размер временного окна в секундах
        score_threshold: Порог по anomaly_score (None = использовать бинарное предсказание)
                        Чем ниже порог, тем выше чувствительность
    """
    print(f"=" * 60)
    print(f"Детекция аномалий в сетевом трафике")
    print(f"Интерфейс: {interface}")
    print(f"Модель: {model_path}")
    print(f"Тип агрегации: time_window")
    print(f"Размер окна: {window_size} секунд")
    print(f"=" * 60)
    print("Нажмите Ctrl+C для остановки\n")
    
    # Загрузка модели
    detector = AnomalyDetector()
    try:
        detector.load(model_path)
        # Устанавливаем порог, если указан (переопределяет сохраненный порог)
        if score_threshold is not None:
            detector.score_threshold = score_threshold
            print(f"Используется порог по score: {score_threshold}")
    except Exception as e:
        print(f"Ошибка при загрузке модели: {e}")
        sys.exit(1)
    
    # Инициализация компонентов
    capture = PacketCapture(interface)
    aggregator = TimeWindowAggregator(window_size=window_size)
    traffic_logger = TrafficLogger(retention_minutes=config.detection.traffic_log_minutes)
    
    anomaly_count = 0
    total_count = 0
    
    def process_packet(packet):
        """Обработка каждого захваченного пакета."""
        nonlocal anomaly_count, total_count

        # Логируем все пакеты для последующего формирования архива
        traffic_logger.add_packet(packet)

        completed = aggregator.add_packet(packet)
        
        if completed:
            # Предсказание аномалий
            results = detector.predict(completed)
            
            for result in results:
                total_count += 1
                if result['is_anomaly']:
                    anomaly_count += 1
                    handle_anomaly(result, traffic_logger)

    def handle_anomaly(result: dict, logger: TrafficLogger):
        """Обработка обнаруженной аномалии: вывод и отправка лога трафика."""
        print_anomaly(result)

        if not config.detection.send_zip_on_anomaly:
            return

        window_end = result.get('window_end', time.time())
        packets_for_zip = logger.get_recent_packets(window_end)

        if not packets_for_zip:
            print("Нет пакетов для формирования архива трафика за указанный период.")
            return

        zip_path = build_zip_from_packets(packets_for_zip)
        if not zip_path:
            print("Не удалось сформировать ZIP-архив с трафиком.")
            return

        window_end_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(window_end))
        message = (
            f"Обнаружена аномалия в окне, заканчивающемся в {window_end_str}. "
            f"В архиве {len(packets_for_zip)} пакетов за последние "
            f"{config.detection.traffic_log_minutes} минут."
        )

        ok = send_zip_to_server(zip_path, config.detection.alert_server_url, message)
        if ok:
            print(f"Архив с трафиком отправлен на {config.detection.alert_server_url}: {zip_path}")
        else:
            print(
                f"Не удалось отправить архив на {config.detection.alert_server_url}. "
                f"Файл сохранён локально: {zip_path}"
            )
    
    try:
        capture.capture_packets_continuous(process_packet)
    except KeyboardInterrupt:
        print(f"\n\nОстановлено пользователем")
        print(f"Всего обработано: {total_count}")
        print(f"Аномалий обнаружено: {anomaly_count}")


def print_anomaly(result: dict):
    """
    Вывод информации об аномалии в консоль.
    
    Args:
        result: Словарь с результатом детекции
    """
    print("\n" + "!" * 60)
    print("ОБНАРУЖЕНА АНОМАЛИЯ")
    print("!" * 60)
    
    window_start = result.get('window_start', 0)
    window_end = result.get('window_end', 0)
    duration = result.get('duration', 0)

    # Форматируем время с миллисекундами для точности
    start_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(window_start))
    end_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(window_end))

    # Добавляем миллисекунды
    start_ms = int((window_start % 1) * 1000)
    end_ms = int((window_end % 1) * 1000)

    print(f"Временное окно: {start_str}.{start_ms:03d} - {end_str}.{end_ms:03d}")
    print(f"Длительность окна: {duration:.3f} секунд (ожидается: {window_end - window_start:.3f})")
    print(f"Количество пакетов: {result.get('packet_count', 0)}")
    print(f"Пакетов в секунду: {result.get('packets_per_second', 0):.2f}")
    print(f"Уникальных IP источников: {result.get('unique_src_ip', 0)}")
    print(f"Уникальных IP назначения: {result.get('unique_dst_ip', 0)}")
    print(f"Уникальных портов источников: {result.get('unique_src_port', 0)}")
    print(f"Уникальных портов назначения: {result.get('unique_dst_port', 0)}")
    print(f"Средняя длина пакета: {result.get('avg_length', 0):.2f} байт")
    print(f"Протокол TCP: {result.get('proto_tcp', 0)} пакетов")
    print(f"Протокол UDP: {result.get('proto_udp', 0)} пакетов")
    print(f"Протокол ICMP: {result.get('proto_icmp', 0)} пакетов")
    
    print(f"Оценка аномальности: {result.get('anomaly_score', 0):.4f}")
    print("!" * 60 + "\n")


def main():
    """Главная функция с парсингом аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description='Детекция аномалий в сетевом трафике с использованием обучения без учителя',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:

  Обучение с сетевого интерфейса:
    sudo python main.py --mode train --interface eth0 --duration 10

  Обучение из одного pcap файла (потоковое, для больших файлов):
    python main.py --mode train --pcap dump.pcap

  Обучение из нескольких pcap файлов (например, дамп с коммутатора):
    python main.py --mode train --pcap dump_001.pcap --pcap dump_002.pcap --model switch_model.pkl

  Обучение из pcap файла с лимитом пакетов:
    python main.py --mode train --pcap dump.pcap --max-packets 1000000

  Детекция аномалий:
    sudo python main.py --mode detect --interface eth0
        """
    )
    
    parser.add_argument(
        '--interface', '-i',
        type=str,
        default=None,
        help=f'Имя сетевого интерфейса (по умолчанию: {config.training.interface})'
    )
    
    parser.add_argument(
        '--mode', '-m',
        type=str,
        choices=['train', 'detect'],
        required=True,
        help='Режим работы: train (обучение) или detect (детекция)'
    )
    
    parser.add_argument(
        '--model', '-M',
        type=str,
        default=config.training.model_path,
        help=f'Путь к файлу модели (по умолчанию: {config.training.model_path})'
    )
    
    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=config.training.duration_minutes,
        help=(
            'Длительность обучения в минутах (только для режима train с интерфейсом, '
            f'по умолчанию: {config.training.duration_minutes})'
        )
    )
    
    parser.add_argument(
        '--window-size', '-w',
        type=float,
        default=config.training.window_size_seconds,
        help=(
            'Размер временного окна в секундах (используется в обоих режимах, '
            f'по умолчанию: {config.training.window_size_seconds})'
        )
    )

    parser.add_argument(
        '--score-threshold', '-t',
        type=float,
        default=config.detection.score_threshold,
        help=(
            'Порог по anomaly_score для детекции (None = использовать бинарное предсказание). '
            'Чем ниже порог, тем выше чувствительность. Для Isolation Forest обычно -0.5 до 0.0'
        )
    )
    
    # Аргументы для работы с pcap файлами
    # Используем action='append', чтобы можно было указать несколько --pcap
    parser.add_argument(
        '--pcap', '-p',
        type=str,
        action='append',
        default=None,
        help=(
            'Путь к pcap/pcapng/cap файлу для обучения (можно указывать несколько раз). '
            'Потоковое чтение — файлы не загружаются в память целиком. '
            'Пример: --pcap f1.pcap --pcap f2.pcap'
        )
    )
    
    parser.add_argument(
        '--max-packets',
        type=int,
        default=None,
        help='Максимальное количество пакетов на файл при чтении из pcap (по умолчанию: все)'
    )
    
    args = parser.parse_args()
    
    # Проверка режима
    if args.mode == 'train':
        if args.pcap:
            # Обучение из одного или нескольких pcap файлов
            # Проверяем существование всех файлов
            missing = [p for p in args.pcap if not os.path.exists(p)]
            if missing:
                print(f"Ошибка: Следующие pcap файлы не найдены:")
                for p in missing:
                    print(f"  - {p}")
                sys.exit(1)
            
            train_model_from_pcaps(
                pcap_paths=args.pcap,
                window_size=args.window_size,
                model_path=args.model,
                max_packets=args.max_packets
            )
        else:
            # Обучение с сетевого интерфейса
            interface = args.interface or config.training.interface
            train_model_from_interface(
                interface=interface,
                duration_minutes=args.duration,
                window_size=args.window_size,
                model_path=args.model
            )
    elif args.mode == 'detect':
        if args.pcap:
            print("Ошибка: Режим detect не поддерживает чтение из pcap файлов. "
                  "Для детекции требуется захват с сетевого интерфейса.")
            print("Используйте: sudo python main.py --mode detect --interface eth0")
            sys.exit(1)
        
        if not os.path.exists(args.model):
            print(f"Ошибка: Файл модели {args.model} не найден.")
            print("Сначала выполните обучение с --mode train")
            sys.exit(1)
        
        interface = args.interface or config.detection.interface
        detect_anomalies(
            interface=interface,
            model_path=args.model,
            window_size=args.window_size,
            score_threshold=args.score_threshold
        )


if __name__ == '__main__':
    main()