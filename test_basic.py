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
        assert True
    except ImportError as e:
        print(f"Ошибка импорта: {e}")
        assert False, f"Не удалось импортировать модуль: {e}"


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
    print(f"Создан PatientVitals для {vitals.patient_id}")


def test_integrity_validator():
    from patient_monitoring_system import IntegrityValidator

    validator = IntegrityValidator()
    assert validator is not None
    assert hasattr(validator, 'validate_all')
    print("IntegrityValidator инициализирован")


if __name__ == "__main__":
    test_imports()
    print("✓ Все импорты работают")

    test_patient_vitals()
    print("✓ PatientVitals создается корректно")

    test_integrity_validator()
    print("✓ IntegrityValidator работает")

    print("\n✅ Все базовые тесты пройдены!")