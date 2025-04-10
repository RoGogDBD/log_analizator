#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            print(f"Error loading file: {e}")
            return None