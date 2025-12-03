#!/usr/bin/env python3
"""
Проверка работы фрагментатора без использования pytest.
"""

import os
import sys
import tempfile
import shutil
import random
from pathlib import Path

# Добавляем src в путь для импорта
sys.path.insert(0, str(Path(__file__).parent))

from src import FAT32Parser, FAT32Analyzer, Fragmentator

def print_header(title):
    """Печатает заголовок раздела."""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)

def check_basic_functionality(image_path):
    """Проверка базовой функциональности фрагментатора."""
    print_header("1. Базовая функциональность")
    
    if not os.path.exists(image_path):
        print(f"ОШИБКА: Файл не найден: {image_path}")
        return False
    
    # 1. Проверяем, что можем открыть парсер
    try:
        with FAT32Parser(image_path, writable=False) as parser:
            parser.parse_boot_sector()
            print("✓ FAT32Parser инициализирован корректно")
            print(f"  Размер кластера: {parser.boot_sector.bytes_per_sector * parser.boot_sector.sectors_per_cluster} байт")
            
            # 2. Проверяем инициализацию фрагментатора
            fragmentator = Fragmentator(parser)
            print("✓ Fragmentator инициализирован корректно")
            
            # 3. Проверяем получение свободных кластеров
            free_clusters = fragmentator.get_free_clusters()
            print(f"✓ Найдено свободных кластеров: {len(free_clusters)}")
            
            # 4. Проверяем анализ образа
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            print(f"✓ Проанализирован образ: {len(report['files'])} файлов, {len(report['dirs'])} директорий")
            
            return True
            
    except Exception as e:
        print(f"✗ Ошибка при проверке базовой функциональности: {e}")
        return False

def check_file_search(image_path):
    """Проверка поиска файлов."""
    print_header("2. Поиск файлов")
    
    try:
        with FAT32Parser(image_path, writable=False) as parser:
            fragmentator = Fragmentator(parser)
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            
            if not report['files']:
                print("⚠ В образе нет файлов для тестирования")
                return False
            
            # Проверяем поиск первого файла
            test_file = report['files'][0]
            result = fragmentator.find_file_entry(test_file['path'])
            
            if result:
                dir_cluster, first_cluster, file_info = result
                print(f"✓ Найден файл: {test_file['path']}")
                print(f"  Директория: кластер {dir_cluster}")
                print(f"  Первый кластер файла: {first_cluster}")
                print(f"  Размер: {file_info['file_size']} байт")
                return True
            else:
                print(f"✗ Не удалось найти файл: {test_file['path']}")
                return False
                
    except Exception as e:
        print(f"✗ Ошибка при поиске файлов: {e}")
        return False

def check_chain_splitting():
    """Проверка разбиения цепочек кластеров."""
    print_header("3. Разбиение цепочек кластеров")
    
    try:
        # Создаем тестовую цепочку из 10 кластеров
        test_chain = list(range(100, 110))
        print(f"Тестовая цепочка: {test_chain}")
        
        # Проверяем разбиение на 3 части
        fragments = Fragmentator._split_chain_random(test_chain, 3)
        print(f"✓ Разбиение на 3 части: {fragments}")
        
        # Проверяем, что все элементы на месте
        flattened = []
        for fragment in fragments:
            flattened.extend(fragment)
        
        if flattened == test_chain:
            print("✓ Все элементы сохранились в правильном порядке")
        else:
            print("✗ Элементы потеряны или порядок нарушен")
            return False
        
        # Проверяем вычисление экстентов
        fragmented_chain = [100, 101, 105, 106, 110, 111, 112]
        extents = Fragmentator._calculate_extents(fragmented_chain)
        print(f"✓ Экстенты для цепочки {fragmented_chain}: {extents}")
        
        if extents == [(100, 2), (105, 2), (110, 3)]:
            print("✓ Экстенты вычислены правильно")
        else:
            print("✗ Ошибка в вычислении экстентов")
            return False
            
        return True
        
    except Exception as e:
        print(f"✗ Ошибка при разбиении цепочек: {e}")
        return False

def test_fragmentation_workflow(original_image_path):
    """Тест полного workflow фрагментации."""
    print_header("4. Полный workflow фрагментации")
    
    # Создаем временную копию образа
    temp_dir = tempfile.mkdtemp(prefix="fat32_test_")
    test_image_path = os.path.join(temp_dir, "test_fragmentation.img")
    
    try:
        # Копируем исходный образ
        shutil.copy2(original_image_path, test_image_path)
        print(f"Создана тестовая копия: {test_image_path}")
        
        # Шаг 1: Анализируем исходное состояние
        with FAT32Parser(test_image_path, writable=False) as parser:
            analyzer = FAT32Analyzer(parser)
            initial_report = analyzer.analyze()
            
            print(f"Исходное состояние: {initial_report['stats']['files_total']} файлов")
            print(f"  Фрагментировано: {initial_report['stats']['files_fragmented']}")
            print(f"  Среднее количество фрагментов: {initial_report['stats']['avg_fragments_per_file']:.2f}")
        
        # Шаг 2: Ищем файл для фрагментации
        suitable_files = []
        with FAT32Parser(test_image_path, writable=False) as parser:
            fragmentator = Fragmentator(parser)
            analyzer = FAT32Analyzer(parser)
            report = analyzer.analyze()
            
            for file_info in report['files']:
                if file_info['fragments'] == 1 and file_info['size_bytes'] > 4096:
                    suitable_files.append(file_info)
        
        if not suitable_files:
            print("⚠ Нет подходящих файлов для фрагментации (нужны файлы > 4KB, не фрагментированные)")
            shutil.rmtree(temp_dir)
            return False
        
        # Выбираем первый подходящий файл
        test_file = suitable_files[0]
        print(f"Выбран файл для фрагментации: {test_file['path']}")
        print(f"  Размер: {test_file['size_bytes']} байт")
        print(f"  Кластеров: {len(test_file['clusters'])}")
        print(f"  Фрагментов: {test_file['fragments']}")
        
        # Шаг 3: Фрагментируем файл
        with FAT32Parser(test_image_path, writable=True) as parser:
            fragmentator = Fragmentator(parser)
            
            # Фрагментируем на 3 части
            num_fragments = min(3, len(test_file['clusters']))
            print(f"\nФрагментируем на {num_fragments} части...")
            
            plan = fragmentator.fragment_file(test_file['path'], num_fragments)
            
            if not plan:
                print("✗ Не удалось фрагментировать файл")
                shutil.rmtree(temp_dir)
                return False
            
            print(f"✓ Файл успешно фрагментирован")
            print(f"  Исходная цепочка: {len(plan.original_clusters)} кластеров")
            print(f"  Новые фрагменты: {len(plan.fragmented_clusters)}")
            for i, fragment in enumerate(plan.fragmented_clusters):
                print(f"    Фрагмент {i+1}: {len(fragment)} кластеров")
            
            parser.sync()
        
        # Шаг 4: Проверяем результат
        with FAT32Parser(test_image_path, writable=False) as parser:
            analyzer = FAT32Analyzer(parser)
            final_report = analyzer.analyze()
            
            # Ищем наш файл в новом отчете
            fragmented_file = None
            for file_info in final_report['files']:
                if file_info['path'] == test_file['path']:
                    fragmented_file = file_info
                    break
            
            if not fragmented_file:
                print("✗ Не удалось найти файл после фрагментации")
                shutil.rmtree(temp_dir)
                return False
            
            print(f"\nРезультат фрагментации:")
            print(f"  Было фрагментов: {test_file['fragments']}")
            print(f"  Стало фрагментов: {fragmented_file['fragments']}")
            
            if fragmented_file['fragments'] > test_file['fragments']:
                print("✓ Фрагментация успешна!")
            else:
                print("⚠ Фрагментация не изменила количество фрагментов")
        
        # Удаляем временную директорию
        shutil.rmtree(temp_dir)
        print(f"\nВременные файлы очищены")
        return True
        
    except Exception as e:
        print(f"✗ Ошибка в workflow фрагментации: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return False

def run_all_checks(image_path):
    """Запускает все проверки."""
    print("ПРОВЕРКА ФРАГМЕНТАТОРА FAT32")
    print("=" * 70)
    
    if not os.path.exists(image_path):
        print(f"ОШИБКА: Файл не найден: {image_path}")
        print("\nСоздайте тестовый образ FAT32 одним из способов:")
        print("1. Используйте утилиту mkfs.fat:")
        print("   dd if=/dev/zero of=test_fat32.img bs=1M count=10")
        print("   mkfs.fat -F32 test_fat32.img")
        print("   # Затем добавьте несколько файлов")
        print("\n2. Или используйте существующий образ FAT32")
        return False
    
    results = []
    
    # Запускаем проверки
    results.append(("Базовая функциональность", check_basic_functionality(image_path)))
    results.append(("Поиск файлов", check_file_search(image_path)))
    results.append(("Разбиение цепочек", check_chain_splitting()))
    results.append(("Полный workflow", test_fragmentation_workflow(image_path)))
    
    # Выводим итоги
    print_header("ИТОГИ ПРОВЕРКИ")
    
    total = len(results)
    passed = sum(1 for _, success in results if success)
    
    for name, success in results:
        status = "✓" if success else "✗"
        print(f"{status} {name}")
    
    print(f"\nРезультат: {passed}/{total} проверок пройдено")
    
    if passed == total:
        print("\n✅ ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ УСПЕШНО!")
        return True
    else:
        print(f"\n❌ НЕ ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ ({total - passed} не пройдено)")
        return False

def create_simple_test_image():
    """Создает простой тестовый образ для демонстрации."""
    print_header("СОЗДАНИЕ ТЕСТОВОГО ОБРАЗА")
    
    test_image_path = "test_simple_fat32.img"
    
    # Размер образа: 2MB (достаточно для тестов)
    image_size = 2 * 1024 * 1024
    
    try:
        # Создаем пустой файл
        with open(test_image_path, 'wb') as f:
            f.write(b'\x00' * image_size)
        
        print(f"Создан пустой образ: {test_image_path}")
        print(f"Размер: {image_size // 1024} KB")
        
        print("\nТеперь создайте файловую систему FAT32:")
        print("\nВ Linux:")
        print(f"  sudo mkfs.fat -F32 {test_image_path}")
        print("\nВ macOS (если установлено dosfstools):")
        print(f"  mkfs.fat -F32 {test_image_path}")
        print("\nВ Windows (через WSL или установите соответствующие утилиты)")
        
        print("\nЗатем добавьте несколько файлов в образ:")
        print("  sudo mount -o loop test_simple_fat32.img /mnt")
        print("  sudo cp some_files/* /mnt/")
        print("  sudo umount /mnt")
        
        return test_image_path
        
    except Exception as e:
        print(f"Ошибка при создании тестового образа: {e}")
        return None

if __name__ == "__main__":
    # Проверяем аргументы командной строки
    if len(sys.argv) > 1:
        image_path = sys.argv[1]
    else:
        # Проверяем существование стандартных тестовых образов
        possible_paths = [
            "test_fat32.img",
            "fat32_test.img",
            "test.img",
            "tests/test_fat32.img"
        ]
        
        image_path = None
        for path in possible_paths:
            if os.path.exists(path):
                image_path = path
                break
        
        if not image_path:
            print("Тестовый образ не найден.")
            response = input("Создать простой тестовый образ? (y/N): ")
            if response.lower() == 'y':
                image_path = create_simple_test_image()
                if not image_path:
                    sys.exit(1)
                print(f"\nЗапустите проверку снова:")
                print(f"  python check_fragmentator.py {image_path}")
                sys.exit(0)
            else:
                print("\nУкажите путь к образу FAT32:")
                print("  python check_fragmentator.py /путь/к/образу.img")
                sys.exit(1)
    
    # Запускаем проверки
    success = run_all_checks(image_path)
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
