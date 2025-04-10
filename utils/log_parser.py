#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from datetime import datetime

class LogParser:
    @staticmethod
    def parse_log(log_text):
        """
        Разбирает содержимое лога в структурированные данные
        
        Аргументы:
            log_text (str): Необработанное содержимое лога
            
        Возвращает:
            list: Список разобранных записей лога
        """
        entries = []
        
        log_blocks = re.split(r'\n\s*\n', log_text.strip())
        
        for block in log_blocks:
            if not block.strip():
                continue
                
            lines = block.strip().split('\n')
            if len(lines) < 2:
                continue
                
            header_match = re.match(r'(\d{2}:\d{2}:\d{2}\.\d{3})\|([^\ ]+)\s+(.+?)\s+\(([^,]+),(\d+)\):(.+)', lines[0])
            if not header_match:
                continue
                
            timestamp, identifier, event_type, source_file, line_number, function = header_match.groups()
            
            hex_data = ""
            for i in range(1, len(lines)):
                if "HEX DUMP" in lines[i]:
                    continue
                hex_match = re.match(r'\w+h\s+([0-9A-F\s]+)\s+.+', lines[i])
                if hex_match:
                    hex_data += hex_match.group(1).strip() + " "
            
            hex_values = [int(x, 16) for x in hex_data.strip().split() if x]
            
            entry = {
                'timestamp': timestamp,
                'timestamp_obj': datetime.strptime(timestamp, '%H:%M:%S.%f'),
                'identifier': identifier,
                'event_type': event_type,
                'source_file': source_file,
                'line_number': line_number,
                'function': function,
                'hex_data': hex_values,
                'raw_block': block
            }
            
            if len(hex_values) > 2:
                entry['event_code'] = hex_values[2]
            
            entries.append(entry)
            
        return entries
    
    @staticmethod
    def analyze_events(parsed_logs, event_codes=None):
        """
        Анализирует логи на наличие определенных событий
        
        Аргументы:
            parsed_logs (list): Список разобранных записей лога
            event_codes (dict): Словарь кодов событий для анализа {код: описание}
            
        Возвращает:
            dict: Результаты анализа для каждого типа события
        """
        if event_codes is None:
            event_codes = {
                0x24: "Результат просчета",
                0x23: "Счет (банкнота)",
                0x30: "Ошибка"
            }
        
        results = {
            'events_by_code': {},
            'event_summary': {}
        }
        
        for code in event_codes:
            results['events_by_code'][code] = []
            
        for entry in parsed_logs:
            if 'event_code' in entry and entry['event_code'] in event_codes:
                code = entry['event_code']
                results['events_by_code'][code].append(entry)
        
        for code, description in event_codes.items():
            events = results['events_by_code'].get(code, [])
            results['event_summary'][code] = {
                'description': description,
                'count': len(events),
                'first_occurrence': min([e['timestamp_obj'] for e in events]) if events else None,
                'last_occurrence': max([e['timestamp_obj'] for e in events]) if events else None,
            }
            
        return results
        
    @staticmethod
    def parse_banknote_info(hex_data):
        """
        Разбирает информацию о банкноте из кода события 0x23
        
        Аргументы:
            hex_data (list): Список шестнадцатеричных значений
            
        Возвращает:
            dict: Разобранная информация о банкноте
        """
        if len(hex_data) < 58:
            return {'error': 'Неполные данные о банкноте'}

        data_start_index = 3
        
        if len(hex_data) < data_start_index + 58:
            return {'error': 'Неполные данные о банкноте'}
            
        data = hex_data[data_start_index:]

        banknote_info = {
            'banknote_no': data[0],
            'recognition_code': data[1:5],
            'recognition_error': data[5:7],
            'encoder': data[7:11],
            'note_destination': data[11],
            'reserved1': data[12],
            'reserved2': data[13:16],
            'serial_size': data[16],
            'serial': data[17:49],
            'denom_info': data[49:53],
            'denom_use_flag': data[53],
            'decimal_point': data[54],
            'banknote_extens': data[55:57],
            'sc_error': data[57]
        }
        
        dest_map = {0: "Reject", 1: "Cassette", 2: "Drum1", 3: "Drum2", 4: "Drum3", 5: "Drum4"}
        banknote_info['destination_text'] = dest_map.get(banknote_info['note_destination'], "Неизвестно")
        
        sc_error_map = {
            0: "Нет", 
            1: "Ошибка распознавания", 
            2: "Результат отклонения - опция SC",
            3: "Результат отклонения - потеря информации распознавания",
            4: "Результат отклонения - Цепочка",
            5: "Результат отклонения - Превышение размера",
            6: "Результат отклонения - Неверный укладчик",
            7: "Результат отклонения - Полная сумма партии",
            8: "Результат отклонения - Полный счетчик номиналов",
            9: "Результат отклонения - Несоответствие номинала банкноты"
        }
        banknote_info['sc_error_text'] = sc_error_map.get(banknote_info['sc_error'], "Неизвестная ошибка")
        
        if banknote_info['serial_size'] > 0 and banknote_info['serial_size'] <= 32:
            serial_bytes = banknote_info['serial'][:banknote_info['serial_size']]
            try:
                banknote_info['serial_text'] = ''.join([chr(b) if 32 <= b <= 126 else '?' for b in serial_bytes])
            except:
                banknote_info['serial_text'] = "Невозможно декодировать"
        else:
            banknote_info['serial_text'] = "Н/Д"
            
        return banknote_info
    
    @staticmethod
    def parse_count_info(hex_data):
        """
        Разбирает информацию о счете из кода события 0x24
        
        Аргументы:
            hex_data (list): Список шестнадцатеричных значений
            
        Возвращает:
            dict: Разобранная информация о счете
        """
        if len(hex_data) < 4: 
            return {'error': 'Неполные данные счета'}
            
        data_start_index = 3
        
        if len(hex_data) < data_start_index + 4:
            return {'error': 'Неполные данные счета'}
            
        data = hex_data[data_start_index:]
        data_length = len(data)
        result = {'format': 'неизвестный', 'raw_data': data}
        
        if data_length >= 10 and data_length < 12:
            result['format'] = 'KD'
            result['insert_count_last'] = data[0]
            result['deposit_count_last'] = data[1]
            result['reject_count_last'] = data[2]
            result['insert_try_count'] = data[3]
            
            if len(data) >= 10:
                result['insert_count_total'] = data[4] + (data[5] << 8)
                result['deposit_count_total'] = data[6] + (data[7] << 8)
                result['reject_count_total'] = data[8] + (data[9] << 8)
                
        elif data_length == 12:
            result['format'] = 'KR1'
            
            result['reject_count'] = data[0] + (data[1] << 8)
            result['cassette_count'] = data[2] + (data[3] << 8)
            result['drum1_count'] = data[4] + (data[5] << 8)
            result['drum2_count'] = data[6] + (data[7] << 8)
            result['drum3_count'] = data[8] + (data[9] << 8)
            result['drum4_count'] = data[10] + (data[11] << 8)
            
        elif data_length >= 15:
            result['format'] = 'KR2'
            
            result['insert_count_last'] = data[0]
            result['reject_count_last'] = data[1]
            
            result['cassette_count_last'] = data[2] + (data[3] << 8)
            
            result['drum_direction'] = "Внесение" if data[4] == 1 else "Выдача"
            
            result['drum1_count_last'] = data[5]
            result['drum2_count_last'] = data[6]
            result['drum3_count_last'] = data[7]
            result['drum4_count_last'] = data[8]
            
            result['cassette_count_total'] = data[9] + (data[10] << 8)
            
            result['drum1_count_total'] = data[11]
            result['drum2_count_total'] = data[12]
            result['drum3_count_total'] = data[13]
            result['drum4_count_total'] = data[14]
        
        return result
    
    @staticmethod
    def parse_error_info(hex_data):
        """
        Разбирает информацию об ошибках из кода события 0x48
        
        Аргументы:
            hex_data (list): Список шестнадцатеричных значений
            
        Возвращает:
            dict: Разобранная информация об ошибках
        """
        if len(hex_data) < 4:
            return {'error': 'Неполные данные об ошибках'}
            
        data_start_index = 3
        
        data = hex_data[data_start_index:]
        result = {'raw_data': data, 'errors_detected': False}

        error_fields = {
            0: {'name': 'reverse_motor', 'description': 'Реверсивный мотор', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            1: {'name': 'insert_motor', 'description': 'Мотор вставки', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            2: {'name': 'main_trans_motor', 'description': 'Основной транспортный мотор', 'error_desc': 'Ошибка', 'scope': 'Общее'},
            3: {'name': 'insert_pusher', 'description': 'Толкатель вставки', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            4: {'name': 'reject_shutter', 'description': 'Шторка отклонения', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            5: {'name': 'rail_switch', 'description': 'Рельсовый переключатель', 'error_desc': 'Открыт', 'scope': 'Общее'},
            6: {'name': 'hopper_sensor', 'description': 'Сенсор лотка', 'error_desc': 'Обнаружен сигнал', 'scope': 'Общее'},
            7: {'name': 'interval_control_sensor', 'description': 'Сенсор контроля интервала', 'error_desc': 'Обнаружен сигнал', 'scope': 'Только серия KDS'},
            8: {'name': 'insert_sensor', 'description': 'Сенсор вставки', 'error_desc': 'Обнаружен сигнал', 'scope': 'Общее'},
            9: {'name': 'sepa_sensor', 'description': 'Сенсор SEPA', 'error_desc': 'Обнаружен сигнал', 'scope': 'Общее'},
            10: {'name': 'reject_counter_sensor', 'description': 'Сенсор счетчика отклонений', 'error_desc': 'Обнаружен сигнал', 'scope': 'Общее'},
            11: {'name': 'deposit_counter_sensor', 'description': 'Сенсор счетчика внесения', 'error_desc': 'Обнаружен сигнал', 'scope': 'Общее'},
            12: {'name': 'reject_pocket_sensor1', 'description': 'Сенсор кармана отклонения 1 (внутренний)', 'error_desc': 'Обнаружен сигнал', 'scope': 'Общее'},
            13: {'name': 'reject_pocket_sensor2', 'description': 'Сенсор кармана отклонения 2 (внешний)', 'error_desc': 'Обнаружен сигнал', 'scope': 'Только серия KDS'},
            14: {'name': 'upper_interface_board_connect', 'description': 'Подключение верхней интерфейсной платы', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            15: {'name': 'reco_communication', 'description': 'Связь с системой распознавания', 'error_desc': 'Ошибка', 'scope': 'Общее'},
            16: {'name': 'fpga_communication', 'description': 'Связь с FPGA', 'error_desc': 'Ошибка', 'scope': 'Общее'},
            17: {'name': 'hsc_communication', 'description': 'Связь с HSC', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            18: {'name': 'safebox_trans_motor', 'description': 'Транспортный мотор сейфа', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            19: {'name': 'safebox_door_switch', 'description': 'Переключатель дверцы сейфа', 'error_desc': 'Открыт', 'scope': 'Общее'},
            20: {'name': 'safebox_deposit_counter_sensor', 'description': 'Сенсор счетчика внесения в сейф', 'error_desc': 'Обнаружен сигнал', 'scope': 'Только серия KDS'},
            21: {'name': 'safebox_full_sensor', 'description': 'Сенсор заполнения сейфа', 'error_desc': 'Полный', 'scope': 'Общее'},
            22: {'name': 'heatsealing_module', 'description': 'Модуль термосклеивания или мотор конверта', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            23: {'name': 'heatsealing_module_rail_switch', 'description': 'Рельсовый переключатель модуля термосклеивания', 'error_desc': 'Открыт', 'scope': 'Только серия KDS'},
            24: {'name': 'canvas_bag_switch', 'description': 'Переключатель холщового мешка или сенсор обнаружения виниловой сумки', 'error_desc': 'Открыт', 'scope': 'Общее'},
            25: {'name': 'envelope_deposit', 'description': 'Внесение конверта (холщовый мешок)', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            26: {'name': 'insert_pusher_up_sensor', 'description': 'Сенсор верхнего положения толкателя вставки', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            27: {'name': 'insert_pusher_down_sensor', 'description': 'Сенсор нижнего положения толкателя вставки', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            28: {'name': 'reject_shutter_open_sensor', 'description': 'Сенсор открытия шторки отклонения', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            29: {'name': 'reject_shutter_close_sensor', 'description': 'Сенсор закрытия шторки отклонения', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            30: {'name': 'insert_motor_check_sensor', 'description': 'Сенсор проверки мотора вставки', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            31: {'name': 'main_trans_motor_check_sensor', 'description': 'Сенсор проверки основного транспортного мотора', 'error_desc': 'Ошибка', 'scope': 'Только серия KDS'},
            32: {'name': 'banknote_trans_fail', 'description': 'Сбой транспортировки банкноты', 'error_desc': 'Ошибка', 'scope': 'Общее'},
            33: {'name': 'cassette_puser_error', 'description': 'Ошибка толкателя кассеты', 'error_desc': 'Ошибка', 'scope': 'Только серия KD-Только кассета'},
            34: {'name': 'jam_sensor', 'description': 'Сенсор замятия', 'error_desc': 'Обнаружен сигнал', 'scope': 'Только серия KD'},
            35: {'name': 'enter_sensor', 'description': 'Сенсор входа', 'error_desc': 'Обнаружен сигнал', 'scope': 'Только серия KD'},
            36: {'name': 'cassette_count_sensor', 'description': 'Сенсор счетчика кассеты', 'error_desc': 'Ошибка', 'scope': 'Только серия KD-Только кассета'},
            37: {'name': 'cassette_banknote_stay_error', 'description': 'Ошибка остановки банкноты в кассете', 'error_desc': 'Ошибка', 'scope': 'Только серия KD-Только кассета'},
            38: {'name': 'l_path_sensor', 'description': 'Сенсор L-пути', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            39: {'name': 'l_jam1_sensor', 'description': 'Сенсор замятия L1', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            40: {'name': 'l_jam2_sensor', 'description': 'Сенсор замятия L2', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            41: {'name': 'l_jam3_sensor', 'description': 'Сенсор замятия L3', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            42: {'name': 'drum1_sensor', 'description': 'Сенсор барабана 1', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            43: {'name': 'drum2_sensor', 'description': 'Сенсор барабана 2', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            44: {'name': 'drum3_sensor', 'description': 'Сенсор барабана 3', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            45: {'name': 'drum4_sensor', 'description': 'Сенсор барабана 4', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            46: {'name': 'l_door_switch', 'description': 'Переключатель L-дверцы', 'error_desc': 'Открыт', 'scope': 'Только серия KR10'},
            47: {'name': 'l_rail_switch', 'description': 'Переключатель L-рельса', 'error_desc': 'Открыт', 'scope': 'Только серия KR10'},
            48: {'name': 'drum1_full_pi', 'description': 'Индикатор заполнения барабана 1', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            49: {'name': 'drum2_full_pi', 'description': 'Индикатор заполнения барабана 2', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            50: {'name': 'drum3_full_pi', 'description': 'Индикатор заполнения барабана 3', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            51: {'name': 'drum4_full_pi', 'description': 'Индикатор заполнения барабана 4', 'error_desc': 'Ошибка', 'scope': 'Только серия KR10'},
            52: {'name': 'reserved1', 'description': 'Зарезервировано', 'error_desc': '', 'scope': ''},
            53: {'name': 'reserved2', 'description': 'Зарезервировано', 'error_desc': '', 'scope': ''},
            54: {'name': 'reserved3', 'description': 'Зарезервировано', 'error_desc': '', 'scope': ''},
            55: {'name': 'reserved4', 'description': 'Зарезервировано', 'error_desc': '', 'scope': ''},
            56: {'name': 'reserved5', 'description': 'Зарезервировано', 'error_desc': '', 'scope': ''},
            57: {'name': 'reserved6', 'description': 'Зарезервировано', 'error_desc': '', 'scope': ''},
            58: {'name': 'reserved7', 'description': 'Зарезервировано', 'error_desc': '', 'scope': ''},
            59: {'name': 'reserved8', 'description': 'Зарезервировано', 'error_desc': '', 'scope': ''}
        }
        
        banknote_trans_fail_desc = {
            0: "Нет",
            1: "Ошибка несоответствия BID",
            2: "Ошибка неправильного укладчика (для разделителя верхнего модуля)",
            3: "Ошибка разрыва банкноты",
            4: "Ошибка двойной цепочки",
            5: "Ошибка темной цепочки",
            6: "Ошибка белой цепочки",
            7: "Ошибка вставки",
            8: "Полная сумма партии",
            0x10: "Ошибка неправильного укладчика при отклонении (для выдачи)",
            0x11: "Ошибка неправильного укладчика кассеты",
            0x12: "Ошибка неправильного укладчика барабана 1",
            0x13: "Ошибка неправильного укладчика барабана 2",
            0x14: "Ошибка неправильного укладчика барабана 3",
            0x15: "Ошибка неправильного укладчика барабана 4"
        }
        
        result['fields'] = {}
        active_errors = []
        
        for i, field_info in error_fields.items():
            if i >= len(data):
                break
                
            field_value = data[i]
            field_name = field_info['name']
            
            result['fields'][field_name] = {
                'value': field_value,
                'description': field_info['description'],
                'error_desc': field_info['error_desc'],
                'scope': field_info['scope']
            }
            
            if field_name == 'banknote_trans_fail' and field_value > 0:
                result['fields'][field_name]['specific_desc'] = banknote_trans_fail_desc.get(field_value, f"Неизвестный код ошибки: {field_value}")
                active_errors.append(f"{field_info['description']}: {result['fields'][field_name]['specific_desc']}")
                result['errors_detected'] = True
                
            elif field_value == 1 and field_info['error_desc']:
                active_errors.append(f"{field_info['description']}: {field_info['error_desc']}")
                result['errors_detected'] = True
        
        result['active_errors'] = active_errors
        result['active_error_count'] = len(active_errors)
        
        return result