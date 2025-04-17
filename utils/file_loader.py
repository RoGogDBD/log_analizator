#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
import os


class FileLoader:
    @staticmethod
    def load_file(file_path):
        """
        Загружает содержимое файла из указанного пути

        Аргументы:
            file_path (str): Путь к загружаемому файлу

        Возвращает:
            str: Содержимое файла или None в случае ошибки
        """
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return file.read()
        except Exception as e:
            os.makedirs("logs", exist_ok=True)
            log_path = os.path.join("logs", "app.log")
            with open(log_path, "a+", encoding="utf-8") as log_file:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_file.write(f"{timestamp}: Error loading file: {e}\n")
            return None
