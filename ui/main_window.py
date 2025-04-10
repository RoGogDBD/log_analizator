#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import (QMainWindow, QTextEdit, QPushButton, QVBoxLayout, 
                             QHBoxLayout, QFileDialog, QWidget, QLabel, QStatusBar,
                             QSpacerItem, QSizePolicy, QTabWidget, QMessageBox,
                             QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon
import os
from utils.file_loader import FileLoader
from utils.log_parser import LogParser

class MainWindow(QMainWindow):
    """
    Главное окно приложения для анализа логов специализированных устройств по обработке банкнот.

    Этот класс предоставляет графический интерфейс для загрузки лог-файлов устройств, их анализа
    и отображения результатов в структурированном виде. Поддерживает работу с несколькими типами событий.

    Поддерживаемые типы событий:
    - 0x24 (36): Результаты просчета банкнот в различных форматах (KD, KR1, KR2)
    - 0x23 (35): Детальная информация о каждой обработанной банкноте
    - 0x48 (72): Ошибки и статусы устройств

    Attributes:
        event_codes (dict): Словарь соответствия кодов событий их описаниям.
        current_file (str): Путь к текущему открытому файлу.
        parsed_logs (list): Список разобранных записей лога.
        text_display (QTextEdit): Область отображения исходного лога.
        line_by_line_display (QTextEdit): Область построчного анализа.
        summary_display (QTextEdit): Область отображения общей статистики.
        event_tabs (dict): Словарь с вкладками для каждого типа события.

    Methods:
        load_file(): Открывает диалог выбора файла и загружает его содержимое.
        analyze_log(): Выполняет анализ загруженного лога и отображает результаты.
        _display_line_by_line_analysis(parsed_logs): Отображает построчный анализ с расшифровкой каждой записи.
        _display_summary(analysis_results): Отображает сводную статистику по логу.
        _display_event_analysis(code, description, events): Отображает анализ для конкретного типа события.
        _decode_count_info(entry): Расшифровывает информацию о просчете банкнот.
        _decode_banknote_info(entry): Расшифровывает информацию о конкретной банкноте.
        _decode_error_info(entry): Расшифровывает информацию об ошибках устройства.
        _format_calculation_results(events): Форматирует результаты просчета банкнот для отображения.
        _format_detailed_accounting(events): Форматирует детальную информацию по обработанным банкнотам.
        _format_errors(events): Форматирует информацию об ошибках для отображения.
        _format_generic_events(events): Форматирует информацию о других типах событий.

    Example:
        app = QApplication(sys.argv)
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec_())
    """
    def __init__(self):
        """
        Инициализирует главное окно приложения и его компоненты.
        
        Настраивает начальные параметры, включая коды событий для анализа.
        """
        super().__init__()
        
        self.event_codes = {
            0x24: "Результат просчета",
            0x23: "Счет (банкнота)",
            0x48: "Ошибка"
        }
        
        self.current_file = None
        self.parsed_logs = []
        self.full_ui_initialized = False
        
        self.init_welcome_ui()
        
    def init_welcome_ui(self):
        """
        Инициализирует начальный интерфейс с большой кнопкой по центру.
        """
        self.setWindowTitle("Анализатор логов")
        self.setGeometry(100, 100, 800, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        layout.addStretch(1)
        
        h_layout = QHBoxLayout()
        h_layout.addStretch(1)
        
        title = QLabel("Анализатор логов")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        description = QLabel("Загрузите лог-файл для начала анализа")
        description_font = QFont()
        description_font.setPointSize(12)
        description.setFont(description_font)
        description.setAlignment(Qt.AlignCenter)
        layout.addWidget(description)
        
        layout.addSpacing(30)
        
        self.welcome_load_button = QPushButton("Загрузить лог-файл")
        self.welcome_load_button.setMinimumSize(300, 100)
        button_font = QFont()
        button_font.setPointSize(14)
        self.welcome_load_button.setFont(button_font)
        self.welcome_load_button.clicked.connect(self.load_file)
        
        h_layout.addWidget(self.welcome_load_button)
        h_layout.addStretch(1)
        
        layout.addLayout(h_layout)
        
        layout.addStretch(1)
        
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Готов к работе")
        
    def init_full_ui(self):
        """
        Инициализирует полный пользовательский интерфейс приложения после загрузки файла.
        """
        if self.full_ui_initialized:
            return
            
        old_central_widget = self.centralWidget()
        
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        button_layout = QHBoxLayout()
        
        self.load_button = QPushButton("Загрузить лог-файл")
        self.load_button.clicked.connect(self.load_file)
        button_layout.addWidget(self.load_button)
        
        self.file_label = QLabel(os.path.basename(self.current_file) if self.current_file else "Файл не выбран")
        button_layout.addWidget(self.file_label)
        
        button_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        
        self.analyze_button = QPushButton("Анализировать")
        self.analyze_button.clicked.connect(self.analyze_log)
        self.analyze_button.setEnabled(self.current_file is not None)
        button_layout.addWidget(self.analyze_button)
        
        main_layout.addLayout(button_layout)
        
        self.tab_widget = QTabWidget()
        
        self.text_display = QTextEdit()
        self.text_display.setReadOnly(True)
        if self.current_file:
            content = FileLoader.load_file(self.current_file)
            if content:
                self.text_display.setPlainText(content)
        self.tab_widget.addTab(self.text_display, "Исходный лог")
        
        self.line_by_line_display = QTextEdit()
        self.line_by_line_display.setReadOnly(True)
        self.tab_widget.addTab(self.line_by_line_display, "Построчный анализ")
        
        self.analysis_tab = QWidget()
        self.analysis_layout = QVBoxLayout(self.analysis_tab)
        
        self.analysis_tabs = QTabWidget()
        
        self.summary_display = QTextEdit()
        self.summary_display.setReadOnly(True)
        self.analysis_tabs.addTab(self.summary_display, "Общие результаты")
        
        self.event_tabs = {}
        for code, description in self.event_codes.items():
            event_display = QTextEdit()
            event_display.setReadOnly(True)
            self.event_tabs[code] = event_display
            self.analysis_tabs.addTab(event_display, f"Событие {hex(code)} ({code}): {description}")
        
        self.analysis_layout.addWidget(self.analysis_tabs)
        self.tab_widget.addTab(self.analysis_tab, "Анализ")
        
        main_layout.addWidget(self.tab_widget)
        
        self.setCentralWidget(central_widget)
        
        if old_central_widget:
            old_central_widget.deleteLater()
            
        self.full_ui_initialized = True
        
    def load_file(self):
        """
        Открывает диалог выбора файла и загружает его содержимое.
        
        При успешной загрузке файла, его содержимое отображается в интерфейсе
        и становится доступной кнопка анализа.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите лог-файл",
            "",
            "Лог-файлы (*.log *.txt);;Все файлы (*)"
        )
        
        if file_path:
            self.current_file = file_path
            
            if not self.full_ui_initialized:
                self.init_full_ui()
            else:
                self.file_label.setText(os.path.basename(file_path))
            
            content = FileLoader.load_file(file_path)
            
            if content:
                self.text_display.setPlainText(content)
                
                self.parsed_logs = LogParser.parse_log(content)
                
                file_size = os.path.getsize(file_path)
                log_count = len(self.parsed_logs)
                self.statusBar.showMessage(f"Загружен файл: {file_path} ({file_size} байт), найдено {log_count} записей")
                
                self.analyze_button.setEnabled(True)
                
                self.tab_widget.setCurrentIndex(0)
            else:
                QMessageBox.critical(self, "Ошибка", "Не удалось загрузить файл!")
    
    def analyze_log(self):
        """
        Выполняет анализ загруженного лога и отображает результаты.
        
        Запускает процесс анализа лога, формирует различные представления
        результатов и отображает их в соответствующих вкладках интерфейса.
        """
        if not self.current_file or not self.parsed_logs:
            return
        
        analysis_results = LogParser.analyze_events(self.parsed_logs, self.event_codes)
        
        self._display_summary(analysis_results)
        
        self._display_line_by_line_analysis(self.parsed_logs)
        
        for code, description in self.event_codes.items():
            self._display_event_analysis(code, description, analysis_results['events_by_code'].get(code, []))
        
        self.tab_widget.setCurrentIndex(1)  
        self.statusBar.showMessage("Анализ логов завершен")

    def _display_line_by_line_analysis(self, parsed_logs):
        """
        Отображает построчный анализ логов с расшифровкой каждой записи
        
        Аргументы:
            parsed_logs (list): Список разобранных записей лога
        """
        html = "<h2>Построчный анализ логов</h2>"
        
        if not parsed_logs:
            html += "<p>Логи не содержат записей для анализа.</p>"
            self.line_by_line_display.setHtml(html)
            return
        
        html += "<div style='font-family: monospace;'>"
        
        for i, entry in enumerate(parsed_logs):
            html += f"<div style='margin-bottom: 20px; border-bottom: 1px solid #ccc; padding-bottom: 10px;'>"
            html += f"<h3>Запись #{i+1}</h3>"
            
            timestamp = entry['timestamp']
            event_type = entry['event_type']
            source = f"{entry['source_file']}:{entry['line_number']}"
            function = entry['function']
            
            html += f"<p><b>Время:</b> {timestamp} | <b>Тип:</b> {event_type} | <b>Источник:</b> {source} | <b>Функция:</b> {function}</p>"
            
            if 'hex_data' in entry and entry['hex_data']:
                hex_str = ' '.join([f"{b:02X}" for b in entry['hex_data']])
                html += f"<p><b>Сырые данные:</b> <span style='color:#666'>{hex_str}</span></p>"
            
            html += "<div style='background-color:#f9f9f9; padding:10px; border-left:3px solid #4CAF50;'>"
            html += "<h4>Расшифровка:</h4>"
            
            if 'event_code' in entry:
                event_code = entry['event_code']
                html += f"<p><b>Код события:</b> {hex(event_code)} ({event_code})"
                
                if event_code in self.event_codes:
                    html += f" - {self.event_codes[event_code]}</p>"
                else:
                    html += " - Неизвестное событие</p>"
                
                if event_code == 0x24:
                    html += self._decode_count_info(entry)
                elif event_code == 0x23:
                    html += self._decode_banknote_info(entry)
                elif event_code == 0x48:
                    html += self._decode_error_info(entry)
                else:
                    html += "<p>Подробная расшифровка недоступна для этого типа события.</p>"
            else:
                html += "<p>Не удалось определить код события.</p>"
                
            html += "</div>"
            
            html += "</div>"
        
        html += "</div>"
        
        self.line_by_line_display.setHtml(html)

    def _decode_count_info(self, entry):
        """
        Расшифровывает и объясняет информацию о просчете банкнот (событие 0x24)
        
        Аргументы:
            entry (dict): Запись лога с данными просчета
            
        Возвращает:
            str: HTML-разметка с расшифрованной информацией
        """
        html = "<div style='margin-left:15px;'>"
        
        try:
            count_data = LogParser.parse_count_info(entry['hex_data'])
            
            if 'error' in count_data:
                return html + f"<p>Ошибка расшифровки данных счета: {count_data['error']}</p></div>"
                
            format_type = count_data.get('format', 'Неизвестный')
            html += f"<p><b>Формат данных:</b> {format_type}</p>"
            
            if format_type == 'KD':
                html += "<p><b>Последний просчет:</b></p>"
                html += "<ul>"
                html += f"<li>Вставлено банкнот: {count_data.get('insert_count_last', 0)}</li>"
                html += f"<li>Внесено в хранилище: {count_data.get('deposit_count_last', 0)}</li>"
                html += f"<li>Отклонено банкнот: {count_data.get('reject_count_last', 0)}</li>"
                html += f"<li>Попыток вставки: {count_data.get('insert_try_count', 0)}</li>"
                html += "</ul>"
                
                html += "<p><b>Общий просчет:</b></p>"
                html += "<ul>"
                html += f"<li>Всего вставлено: {count_data.get('insert_count_total', 0)}</li>"
                html += f"<li>Всего внесено: {count_data.get('deposit_count_total', 0)}</li>"
                html += f"<li>Всего отклонено: {count_data.get('reject_count_total', 0)}</li>"
                html += "</ul>"
                
            elif format_type == 'KR1':
                html += "<p><b>Результаты просчета:</b></p>"
                html += "<ul>"
                html += f"<li>Отклонено банкнот: {count_data.get('reject_count', 0)}</li>"
                html += f"<li>Помещено в кассету: {count_data.get('cassette_count', 0)}</li>"
                html += f"<li>Помещено в Drum1: {count_data.get('drum1_count', 0)}</li>"
                html += f"<li>Помещено в Drum2: {count_data.get('drum2_count', 0)}</li>"
                html += f"<li>Помещено в Drum3: {count_data.get('drum3_count', 0)}</li>"
                html += f"<li>Помещено в Drum4: {count_data.get('drum4_count', 0)}</li>"
                html += "</ul>"
                
            elif format_type == 'KR2':
                direction = count_data.get('drum_direction', 'Неизвестно')
                html += f"<p><b>Направление барабанов:</b> {direction}</p>"
                
                html += "<p><b>Последний просчет:</b></p>"
                html += "<ul>"
                html += f"<li>Вставлено банкнот: {count_data.get('insert_count_last', 0)}</li>"
                html += f"<li>Отклонено банкнот: {count_data.get('reject_count_last', 0)}</li>"
                html += f"<li>Помещено в кассету: {count_data.get('cassette_count_last', 0)}</li>"
                html += f"<li>Помещено в Drum1: {count_data.get('drum1_count_last', 0)}</li>"
                html += f"<li>Помещено в Drum2: {count_data.get('drum2_count_last', 0)}</li>"
                html += f"<li>Помещено в Drum3: {count_data.get('drum3_count_last', 0)}</li>"
                html += f"<li>Помещено в Drum4: {count_data.get('drum4_count_last', 0)}</li>"
                html += "</ul>"
                
                html += "<p><b>Общее количество в устройстве:</b></p>"
                html += "<ul>"
                html += f"<li>В кассете: {count_data.get('cassette_count_total', 0)}</li>"
                html += f"<li>В Drum1: {count_data.get('drum1_count_total', 0)}</li>"
                html += f"<li>В Drum2: {count_data.get('drum2_count_total', 0)}</li>"
                html += f"<li>В Drum3: {count_data.get('drum3_count_total', 0)}</li>"
                html += f"<li>В Drum4: {count_data.get('drum4_count_total', 0)}</li>"
                html += "</ul>"
        except Exception as e:
            html += f"<p>Ошибка при расшифровке данных: {str(e)}</p>"
        
        html += "</div>"
        return html

    def _decode_banknote_info(self, entry):
        """
        Расшифровывает и объясняет информацию о банкноте (событие 0x23)
        
        Аргументы:
            entry (dict): Запись лога с данными о банкноте
            
        Возвращает:
            str: HTML-разметка с расшифрованной информацией
        """
        html = "<div style='margin-left:15px;'>"
        
        try:
            banknote_data = LogParser.parse_banknote_info(entry['hex_data'])
            
            if 'error' in banknote_data:
                return html + f"<p>Ошибка расшифровки данных банкноты: {banknote_data['error']}</p></div>"
            
            html += f"<p><b>Номер банкноты:</b> {banknote_data['banknote_no']}</p>"
            
            sc_error = banknote_data['sc_error']
            sc_error_text = banknote_data.get('sc_error_text', 'Неизвестно')
            
            if sc_error == 0:
                html += "<p><b>Статус:</b> <span style='color:green'>Успешно</span></p>"
            else:
                html += f"<p><b>Статус:</b> <span style='color:red'>Ошибка {sc_error}: {sc_error_text}</span></p>"
            
            dest = banknote_data['note_destination']
            dest_text = banknote_data.get('destination_text', 'Неизвестно')
            html += f"<p><b>Назначение:</b> {dest_text} (код: {dest})</p>"
            
            serial = banknote_data.get('serial_text', 'Н/Д')
            html += f"<p><b>Серийный номер:</b> {serial}</p>"
            
            recog_code = ' '.join([f"{b:02X}" for b in banknote_data['recognition_code']])
            html += f"<p><b>Код распознавания:</b> {recog_code}</p>"
            
            recog_error = ' '.join([f"{b:02X}" for b in banknote_data['recognition_error']])
            html += f"<p><b>Код ошибки распознавания:</b> {recog_error}</p>"
            
            html += "<p><b>Дополнительные данные:</b></p>"
            html += "<ul>"
            html += f"<li>Encoder: {' '.join([f'{b:02X}' for b in banknote_data['encoder']])}</li>"
            html += f"<li>Denom info: {' '.join([f'{b:02X}' for b in banknote_data['denom_info']])}</li>"
            html += f"<li>Decimal point: {banknote_data['decimal_point']}</li>"
            html += f"<li>Denom use flag: {banknote_data['denom_use_flag']}</li>"
            html += "</ul>"
        except Exception as e:
            html += f"<p>Ошибка при расшифровке данных: {str(e)}</p>"
        
        html += "</div>"
        return html

    def _decode_error_info(self, entry):
        """
        Расшифровывает и объясняет информацию об ошибках (событие 0x48)
        
        Аргументы:
            entry (dict): Запись лога с данными об ошибках
            
        Возвращает:
            str: HTML-разметка с расшифрованной информацией
        """
        html = "<div style='margin-left:15px;'>"
        
        try:
            error_data = LogParser.parse_error_info(entry['hex_data'])
            
            if 'error' in error_data:
                return html + f"<p>Ошибка расшифровки данных: {error_data['error']}</p></div>"
            
            error_count = error_data.get('active_error_count', 0)
            
            if error_count > 0:
                html += f"<p><b>Обнаружены ошибки:</b> <span style='color:red'>{error_count}</span></p>"
                
                html += "<p><b>Активные ошибки:</b></p>"
                html += "<ul style='color:red'>"
                for error in error_data.get('active_errors', []):
                    html += f"<li>{error}</li>"
                html += "</ul>"
            else:
                html += "<p><b>Статус устройства:</b> <span style='color:green'>Нормальное состояние, ошибок не обнаружено</span></p>"
            
            html += "<p><b>Подробная информация о статусе компонентов:</b></p>"
            html += "<table border='1' cellpadding='3' style='font-size:90%'>"
            html += "<tr><th>Компонент</th><th>Статус</th><th>Область применения</th></tr>"
            
            for field_name, field_data in error_data.get('fields', {}).items():
                if field_name.startswith('reserved'):
                    continue
                    
                component = field_data['description']
                scope = field_data['scope']
                
                if field_name == 'banknote_trans_fail' and field_data['value'] > 0:
                    status = field_data.get('specific_desc', "Ошибка")
                    color = "red"
                elif field_data['value'] == 1:
                    status = field_data['error_desc']
                    color = "red"
                else:
                    status = "Нормально"
                    color = "green"
                    
                html += f"<tr><td>{component}</td><td style='color:{color}'>{status}</td><td>{scope}</td></tr>"
                
            html += "</table>"
            
            html += "<p><details><summary>Сырые данные</summary>"
            html += f"<pre>{' '.join([f'{b:02X}' for b in error_data['raw_data']])}</pre>"
            html += "</details></p>"
            
        except Exception as e:
            html += f"<p>Ошибка при расшифровке данных: {str(e)}</p>"
        
        html += "</div>"
        return html

    def _display_summary(self, analysis_results):
        """
        Отображает сводную информацию о результатах анализа логов
        
        Аргументы:
            analysis_results (dict): Результаты анализа логов
        """
        html = "<h2>Сводка анализа логов</h2>"
        
        html += f"<p><b>Всего записей в логе:</b> {len(self.parsed_logs)}</p>"
        
        html += "<h3>Сводка по событиям</h3>"
        html += "<table border='1' cellpadding='5' width='100%'>"
        html += "<tr><th>Код события</th><th>Описание</th><th>Количество</th><th>Первое появление</th><th>Последнее появление</th></tr>"
        
        for code, data in analysis_results['event_summary'].items():
            description = data['description']
            count = data['count']
            first = data['first_occurrence'].strftime('%H:%M:%S.%f')[:-3] if data['first_occurrence'] else 'н/д'
            last = data['last_occurrence'].strftime('%H:%M:%S.%f')[:-3] if data['last_occurrence'] else 'н/д'
            
            html += f"<tr><td>{hex(code)} ({code})</td><td>{description}</td><td>{count}</td><td>{first}</td><td>{last}</td></tr>"
            
        html += "</table>"
        
        self.summary_display.setHtml(html)
    
    def _display_event_analysis(self, code, description, events):
        """
        Отображает анализ для конкретного типа события
        
        Аргументы:
            code (int): Код события
            description (str): Описание события
            events (list): Список событий данного типа
        """
        if code not in self.event_tabs:
            return
        
        html = f"<h2>Событие {hex(code)} ({code}): {description}</h2>"
        html += f"<p><b>Всего найдено:</b> {len(events)} событий</p>"
        
        if not events:
            html += "<p>События данного типа не обнаружены в логе.</p>"
            self.event_tabs[code].setHtml(html)
            return
        
        if code == 0x24:
            html += self._format_calculation_results(events)
        elif code == 0x23:
            html += self._format_detailed_accounting(events)
        elif code == 0x48:
            html += self._format_errors(events)
        else:
            html += self._format_generic_events(events)
        
        self.event_tabs[code].setHtml(html)
    
    def _format_calculation_results(self, events):
        """
        Форматирует результаты просчета банкнот (событие 0x24)
        
        Аргументы:
            events (list): Список событий просчета
            
        Возвращает:
            str: HTML-разметка с отформатированными результатами
        """
        html = "<h3>Результаты просчета банкнот</h3>"
        
        if not events:
            html += "<p>События данного типа не обнаружены в логе.</p>"
            return html
        
        html += f"<p><b>Всего просчетов:</b> {len(events)}</p>"
        
        html += "<table border='1' cellpadding='5' width='100%'>"
        html += "<tr><th>Время</th><th>Формат</th><th>Последний просчет</th><th>Общий просчет</th><th>Подробности</th></tr>"
        
        for event in events:
            timestamp = event['timestamp']
            
            count_data = LogParser.parse_count_info(event['hex_data'])
            
            if 'error' in count_data:
                html += f"<tr><td>{timestamp}</td><td colspan='4'>Ошибка парсинга: {count_data['error']}</td></tr>"
                continue
            
            format_type = count_data.get('format', 'Неизвестный')
            
            last_count = ""
            total_count = ""
            details = ""
            
            if format_type == 'KD':
                last_count = (
                    f"Вставлено: {count_data.get('insert_count_last', 0)}<br>"
                    f"Внесено: {count_data.get('deposit_count_last', 0)}<br>"
                    f"Отклонено: {count_data.get('reject_count_last', 0)}"
                )
                
                total_count = (
                    f"Вставлено: {count_data.get('insert_count_total', 0)}<br>"
                    f"Внесено: {count_data.get('deposit_count_total', 0)}<br>"
                    f"Отклонено: {count_data.get('reject_count_total', 0)}"
                )
                
                details = f"Попыток вставки: {count_data.get('insert_try_count', 0)}"
                
            elif format_type == 'KR1':
                last_count = (
                    f"Отклонено: {count_data.get('reject_count', 0)}<br>"
                    f"Кассета: {count_data.get('cassette_count', 0)}"
                )
                
                total_count = (
                    f"Drum1: {count_data.get('drum1_count', 0)}<br>"
                    f"Drum2: {count_data.get('drum2_count', 0)}<br>"
                    f"Drum3: {count_data.get('drum3_count', 0)}<br>"
                    f"Drum4: {count_data.get('drum4_count', 0)}"
                )
                
            elif format_type == 'KR2':
                last_count = (
                    f"Вставлено: {count_data.get('insert_count_last', 0)}<br>"
                    f"Отклонено: {count_data.get('reject_count_last', 0)}<br>"
                    f"Кассета: {count_data.get('cassette_count_last', 0)}<br>"
                    f"Drum1: {count_data.get('drum1_count_last', 0)}<br>"
                    f"Drum2: {count_data.get('drum2_count_last', 0)}<br>"
                    f"Drum3: {count_data.get('drum3_count_last', 0)}<br>"
                    f"Drum4: {count_data.get('drum4_count_last', 0)}"
                )
                
                total_count = (
                    f"Кассета: {count_data.get('cassette_count_total', 0)}<br>"
                    f"Drum1: {count_data.get('drum1_count_total', 0)}<br>"
                    f"Drum2: {count_data.get('drum2_count_total', 0)}<br>"
                    f"Drum3: {count_data.get('drum3_count_total', 0)}<br>"
                    f"Drum4: {count_data.get('drum4_count_total', 0)}"
                )
                
                details = f"Направление: {count_data.get('drum_direction', 'Неизвестно')}"
            
            html += f"<tr><td>{timestamp}</td><td>{format_type}</td><td>{last_count}</td><td>{total_count}</td><td>{details}</td></tr>"
            
        html += "</table>"
        return html
    
    def _format_detailed_accounting(self, events):
        """
        Форматирует детальную информацию по обработанным банкнотам (событие 0x23)
        
        Аргументы:
            events (list): Список событий с информацией о банкнотах
            
        Возвращает:
            str: HTML-разметка с отформатированной информацией
        """
        html = "<h3>Подробная информация по счету банкнот</h3>"
        
        if not events:
            html += "<p>События данного типа не обнаружены в логе.</p>"
            return html
        
        html += f"<p><b>Всего банкнот обработано:</b> {len(events)}</p>"
        
        html += "<table border='1' cellpadding='5' width='100%'>"
        html += "<tr><th>Время</th><th>№ банкноты</th><th>Результат</th><th>Код распознавания</th><th>Назначение</th><th>Серийный номер</th><th>Информация</th></tr>"
        
        for event in events:
            timestamp = event['timestamp']
            
            banknote_data = LogParser.parse_banknote_info(event['hex_data'])
            
            if 'error' in banknote_data:
                html += f"<tr><td>{timestamp}</td><td colspan='6'>Ошибка парсинга: {banknote_data['error']}</td></tr>"
                continue
            
            banknote_no = banknote_data['banknote_no']
            
            if banknote_data['sc_error'] == 0:
                result = "<span style='color:green'>Успешно</span>"
            else:
                result = f"<span style='color:red'>Ошибка: {banknote_data['sc_error_text']}</span>"
                
            recog_code = ' '.join([f"{b:02X}" for b in banknote_data['recognition_code']])
            
            destination = banknote_data['destination_text']
            serial = banknote_data['serial_text']
            
            denom_info = ' '.join([f"{b:02X}" for b in banknote_data['denom_info']])
            info = (
                f"Denom: {denom_info}<br>"
                f"Ошибка распознавания: {' '.join([f'{b:02X}' for b in banknote_data['recognition_error']])}<br>"
                f"Энкодер: {' '.join([f'{b:02X}' for b in banknote_data['encoder']])}"
            )
            
            html += f"<tr><td>{timestamp}</td><td>{banknote_no}</td><td>{result}</td><td>{recog_code}</td><td>{destination}</td><td>{serial}</td><td>{info}</td></tr>"
            
        html += "</table>"
        return html
    
    def _format_errors(self, events):
        """
        Форматирует информацию об ошибках устройства (событие 0x48)
        
        Аргументы:
            events (list): Список событий с ошибками
            
        Возвращает:
            str: HTML-разметка с отформатированной информацией об ошибках
        """
        html = "<h3>Отчет об ошибках системы</h3>"
        
        if not events:
            html += "<p>События об ошибках не обнаружены в логе.</p>"
            return html
        
        html += f"<p><b>Всего записей об ошибках:</b> {len(events)}</p>"
        
        html += "<table border='1' cellpadding='5' width='100%'>"
        html += "<tr><th>Время</th><th>Кол-во ошибок</th><th>Основные проблемы</th><th>Действия</th></tr>"
        
        for event in events:
            timestamp = event['timestamp']
            
            error_data = LogParser.parse_error_info(event['hex_data'])
            
            if 'error' in error_data:
                html += f"<tr><td>{timestamp}</td><td colspan='3'>Ошибка парсинга: {error_data['error']}</td></tr>"
                continue
            
            error_count = error_data.get('active_error_count', 0)
            
            main_issues = ""
            if error_count > 0:
                active_errors = error_data.get('active_errors', [])
                display_errors = active_errors[:3]
                if len(active_errors) > 3:
                    display_errors.append(f"...и еще {len(active_errors) - 3}")
                    
                main_issues = "<ul>" + "".join([f"<li>{error}</li>" for error in display_errors]) + "</ul>"
            else:
                main_issues = "<span style='color:green'>Нормальное состояние</span>"
            
            actions = ""
            if error_count > 0:
                actions = "<ul>"
                
                if any('sensor' in e.lower() for e in error_data.get('active_errors', [])):
                    actions += "<li>Проверить и очистить сенсоры устройства</li>"
                    
                if any('jam' in e.lower() for e in error_data.get('active_errors', [])):
                    actions += "<li>Проверить на замятие банкнот</li>"
                    
                if any('motor' in e.lower() for e in error_data.get('active_errors', [])):
                    actions += "<li>Проверить работу двигателей</li>"
                    
                if any('communication' in e.lower() for e in error_data.get('active_errors', [])):
                    actions += "<li>Проверить подключение кабелей и перезагрузить устройство</li>"
                    
                if any('switch' in e.lower() or 'door' in e.lower() for e in error_data.get('active_errors', [])):
                    actions += "<li>Проверить закрытие всех дверец и крышек</li>"
                    
                actions += "</ul>"
            else:
                actions = "Действия не требуются"
            
            error_cell_color = "red" if error_count > 0 else "green"
            html += f"<tr><td>{timestamp}</td><td style='color:{error_cell_color}'>{error_count}</td><td>{main_issues}</td><td>{actions}</td></tr>"
        
        html += "</table>"
        
        html += "<h4>Справка по основным кодам ошибок:</h4>"
        html += "<ul>"
        html += "<li><b>BID Mismatch Error</b> - Несоответствие идентификатора банкноты</li>"
        html += "<li><b>Wrong Stacker Error</b> - Ошибка подачи банкноты в неправильный накопитель</li>"
        html += "<li><b>Banknote Tear Error</b> - Обнаружена порванная банкнота</li>"
        html += "<li><b>Chain Error</b> - Проблема с последовательностью обработки банкнот</li>"
        html += "<li><b>Sensor Detected</b> - Сенсор обнаружил нештатную ситуацию</li>"
        html += "</ul>"
        
        return html
    
    def _format_generic_events(self, events):
        """
        Форматирует информацию о стандартных событиях без специальной обработки
        
        Аргументы:
            events (list): Список событий для форматирования
            
        Возвращает:
            str: HTML-разметка с отформатированной информацией
        """
        html = "<table border='1' cellpadding='5' width='100%'>"
        html += "<tr><th>Время</th><th>Идентификатор</th><th>Тип события</th><th>Данные</th></tr>"
        
        for event in events:
            timestamp = event['timestamp']
            identifier = event['identifier']
            event_type = event['event_type']
            data = ' '.join([f"{b:02X}" for b in event['hex_data']])
            
            html += f"<tr><td>{timestamp}</td><td>{identifier}</td><td>{event_type}</td><td>{data}</td></tr>"
            
        html += "</table>"
        return html