#!/usr/bin/env python3
"""
Тесты для CI/CD пайплайна
"""

import sys

sys.path.append('.')


def test_imports():
    try:
        from patient_monitoring_system import (
            PatientVitals, IntegrityAlert, AccessLog, User,
            IntegrityValidator, MultiLevelCache, ConfidentialityManager,
            PatientMonitoringSystem
        )
        imported_classes = [
            PatientVitals, IntegrityAlert, AccessLog, User,
            IntegrityValidator, MultiLevelCache, ConfidentialityManager,
            PatientMonitoringSystem
        ]

        for cls in imported_classes:
            if cls is None:
                raise ValueError(f"Класс {cls} не загружен")

        print(f"✓ Успешно импортировано {len(imported_classes)} классов")
        return True
    except ImportError as e:
        print(f"✗ Ошибка импорта: {e}")
        return False
    except Exception as e:
        print(f"✗ Ошибка при проверке классов: {e}")
        return False


def test_patient_vitals():
    from datetime import datetime
    from patient_monitoring_system import PatientVitals

    vitals = PatientVitals(
        patient_id="TEST_001",
        timestamp=datetime.now(),
        heart_rate=75,
        systolic_bp=120,
        diastolic_bp=80,
        oxygen_saturation=98.0,
        respiratory_rate=16
    )

    assert vitals.patient_id == "TEST_001"
    assert vitals.heart_rate == 75
    assert vitals.oxygen_saturation == 98.0
    print(f"✓ Создан PatientVitals для {vitals.patient_id}")
    return vitals


def test_integrity_validator():
    from patient_monitoring_system import IntegrityValidator

    validator = IntegrityValidator()
    assert validator is not None
    assert hasattr(validator, 'validate_all')
    print("✓ IntegrityValidator инициализирован")
    return validator


def test_system_creation():
    from patient_monitoring_system import PatientMonitoringSystem

    system = PatientMonitoringSystem()
    assert system is not None
    assert hasattr(system, 'process_patient_data')
    assert hasattr(system, 'integrity_validator')
    assert hasattr(system, 'cache_manager')
    assert hasattr(system, 'confidentiality_manager')
    print("✓ PatientMonitoringSystem создана")
    return system


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("ЗАПУСК ТЕСТОВ ДЛЯ CI/CD")
    print("=" * 50)

    all_passed = True

    print("\n1. Тест импортов:")
    if test_imports():
        print("   ✅ PASS")
    else:
        print("   ❌ FAIL")
        all_passed = False

    print("\n2. Тест создания PatientVitals:")
    try:
        vitals = test_patient_vitals()
        print("   ✅ PASS")
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        all_passed = False

    print("\n3. Тест создания IntegrityValidator:")
    try:
        validator = test_integrity_validator()
        print("   ✅ PASS")
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        all_passed = False

    print("\n4. Тест создания полной системы:")
    try:
        system = test_system_creation()
        print("   ✅ PASS")
    except Exception as e:
        print(f"   ❌ FAIL: {e}")
        all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        print("=" * 50 + "\n")
        sys.exit(0)
    else:
        print("❌ НЕКОТОРЫЕ ТЕСТЫ ПРОВАЛЕНЫ")
        print("=" * 50 + "\n")
        sys.exit(1)