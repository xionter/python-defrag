#!/usr/bin/env python3

import os
import sys
import struct
import random
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from src.fat32_parser import FAT32Parser
    from src.analyser import FAT32Analyzer
    from src.fragmentator import Fragmentator, FragmentationPlan
except ImportError as e:
    print(f"Ошибка импорта: {e}")
    sys.exit(1)

def test_chain_splitting():
    print("\n=== Тест разбиения цепочек кластеров ===")
    
    class MockParser:
        def __init__(self):
            self.boot_sector = None
    
    mock_parser = MockParser()
    fragmentator = Fragmentator(mock_parser)
    
    test_chain = list(range(100, 120))
    print(f"Тестовая цепочка: {test_chain}")
    
    fragments = fragmentator._split_chain_random(test_chain, 3)
    print(f"Разбиение на 3 части: {fragments}")
    
    flattened = []
    for fragment in fragments:
        flattened.extend(fragment)
    
    if flattened == test_chain:
        print("Все элементы сохранились в правильном порядке")
    else:
        print("Ошибка: элементы потеряны или порядок нарушен")
        return False
    
    fragmented_chain = [100, 101, 105, 106, 110, 111, 112]
    extents = fragmentator._calculate_extents(fragmented_chain)
    print(f"Экстенты для цепочки {fragmented_chain}: {extents}")
    
    expected_extents = [(100, 2), (105, 2), (110, 3)]
    if extents == expected_extents:
        print("Экстенты вычислены правильно")
    else:
        print(f"Ошибка: ожидалось {expected_extents}, получено {extents}")
        return False
    
    return True

def test_file_fragmentation(image_path):
    print("\n=== Тест фрагментации файла ===")
    
    if not os.path.exists(image_path):
        print(f"Файл не найден: {image_path}")
        return False
    
    temp_dir = tempfile.mkdtemp(prefix="fat32_test_")
    test_copy = os.path.join(temp_dir, "test_fragmentation.img")
    
    try:
        shutil.copy2(image_path, test_copy)
        print(f"Создана тестовая копия: {test_copy}")
        
        with FAT32Parser(test_copy, writable=False) as parser:
            analyzer = FAT32Analyzer(parser)
            initial_report = analyzer.analyze()
            
            print(f"Файлов в образе: {initial_report['stats']['files_total']}")
            print(f"Фрагментировано: {initial_report['stats']['files_fragmented']}")
            
            suitable_files = []
            for file_info in initial_report['files']:
                if file_info['fragments'] == 1 and file_info['size_bytes'] > 2048:
                    suitable_files.append(file_info)
            
            if not suitable_files:
                print("Нет подходящих файлов для фрагментации")
                print("Нужны файлы > 2KB, не фрагментированные")
                return False
            
            test_file = suitable_files[0]
            print(f"\nВыбран файл для теста: {test_file['path']}")
            print(f"Размер: {test_file['size_bytes']} байт")
            print(f"Кластеров: {len(test_file['clusters'])}")
            print(f"Фрагментов: {test_file['fragments']}")
        
        with FAT32Parser(test_copy, writable=True) as parser:
            fragmentator = Fragmentator(parser)
            
            num_clusters = len(test_file['clusters'])
            num_fragments = min(3, max(2, num_clusters // 2))
            
            print(f"\nФрагментируем на {num_fragments} части...")
            plan = fragmentator.fragment_file(test_file['path'], num_fragments)
            
            if not plan:
                print("Не удалось фрагментировать файл")
                return False
            
            print(f"Файл успешно фрагментирован")
            print(f"Исходная цепочка: {len(plan.original_clusters)} кластеров")
            print(f"Новые фрагменты: {len(plan.fragmented_clusters)}")
            
            for i, fragment in enumerate(plan.fragmented_clusters):
                print(f"Фрагмент {i+1}: {len(fragment)} кластеров (первые: {fragment[:3]})")
            
            parser.sync()
        
        with FAT32Parser(test_copy, writable=False) as parser:
            analyzer = FAT32Analyzer(parser)
            final_report = analyzer.analyze()
            
            fragmented_file = None
            for file_info in final_report['files']:
                if file_info['path'] == test_file['path']:
                    fragmented_file = file_info
                    break
            
            if not fragmented_file:
                print("Не удалось найти файл после фрагментации")
                return False
            
            if fragmented_file['fragments'] > test_file['fragments']:
                print("Фрагментация успешна!")
            else:
                print("Фрагментация не изменила количество фрагментов")
        
        return True
        
    except Exception as e:
        print(f"Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def test_free_clusters_detection(image_path):
    print("\n=== Тест обнаружения свободных кластеров ===")
    
    try:
        with FAT32Parser(image_path, writable=False) as parser:
            fragmentator = Fragmentator(parser)
            free_clusters = fragmentator.get_free_clusters()
            
            print(f"Найдено свободных кластеров: {len(free_clusters)}")
            
            if free_clusters:
                print(f"Первые 10: {free_clusters[:10]}")
                print(f"Последние 10: {free_clusters[-10:]}")
                print(f"Всего от {min(free_clusters)} до {max(free_clusters)}")
                return True
            else:
                print("Свободных кластеров не найдено")
                return False
                
    except Exception as e:
        print(f"✗ Ошибка: {e}")
        return False

def test_file_info_extraction(image_path):
    print("\n=== Тест получения информации о файле ===")
    
    try:
        with FAT32Parser(image_path, writable=False) as parser:
            fragmentator = Fragmentator(parser)
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            
            if not report['files']:
                print("В образе нет файлов")
                return False
            
            test_file = report['files'][0]
            file_info = fragmentator.get_file_info(test_file['path'])
            
            if file_info:
                print(f"Файл: {file_info['path']}")
                print(f"Размер: {file_info['size_bytes']} байт")
                print(f"Первый кластер: {file_info['first_cluster']}")
                print(f"Всего кластеров: {len(file_info['clusters'])}")
                print(f"Фрагментов: {file_info['fragments']}")
                
                if file_info['extents']:
                    print(f"Экстенты: {file_info['extents']}")
                
                return True
            else:
                print(f"Не удалось получить информацию о файле: {test_file['path']}")
                return False
                
    except Exception as e:
        print(f"Ошибка: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        sys.exit(1)
    
    image_path = sys.argv[1]
    
    if not os.path.exists(image_path):
        print(f"не найден: {image_path}")
        sys.exit(1)
    
    print(f"Тестирование фрагментатора на образе: {image_path}")
    print("=" * 60)
    
    test_results = []
    
    test_results.append(("Разбиение цепочек", test_chain_splitting()))
    
    test_results.append(("Обнаружение свободных кластеров", 
                        test_free_clusters_detection(image_path)))
    
    test_results.append(("Получение информации о файле",
                        test_file_info_extraction(image_path)))
    
    test_results.append(("Фрагментация файла",
                        test_file_fragmentation(image_path)))
if __name__ == "__main__":
    sys.exit(main())
