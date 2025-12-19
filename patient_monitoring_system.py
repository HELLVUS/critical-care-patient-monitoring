#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Система мониторинга пациентов в реанимации с ИИ
Medical Patient Monitoring System with AI for ICU
=======================================================

Тема: Информационная безопасность интеллектуальных систем
Предмет: Управление инцидентами ИБ с применением ИИ
Организация: Система мониторинга жизненных показателей пациентов в отделении реанимации

Триада безопасности CIA:
  C (Confidentiality) - Конфиденциальность: RBAC, UEBA, AES-GCM шифрование
  I (Integrity)       - Целостность: валидация датчиков, кросс-датчиковый анализ, тренды, EWMA
  A (Availability)    - Доступность: многоуровневое кеширование с TTL и LRU

Author: Васильков Алексей, Группа БСМО-12-25
Date: 2025
"""

import hashlib
import hmac
import json
import time
import random
import logging
import os
from datetime import datetime, timedelta
from collections import deque, OrderedDict
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict

# Попытка импорта cryptography для AES-GCM
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Попытка импорта matplotlib для графиков
try:
    import matplotlib
    matplotlib.use('Agg')  # Неинтерактивный бэкенд
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Установка детерминированного seed
random.seed(42)

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

# Пороги для проверки целостности (настраиваемые)
INTEGRITY_CONFIG = {
    'heart_rate_min': 40,
    'heart_rate_max': 250,  # >= 250 считается ошибкой
    'systolic_bp_max': 240,
    'diastolic_bp_max': 160,
    'oxygen_saturation_min': 50,
    'oxygen_saturation_max': 100,
    'rate_of_change_hr_threshold': 30,  # ударов в минуту за минуту
    'rate_of_change_o2_threshold': 5,  # процентов за минуту
    'rate_of_change_bp_threshold': 20,  # мм рт.ст. за минуту
    'cross_sensor_n_samples': 5,  # N последовательных измерений для проверки
    'ewma_alpha': 0.3,  # Коэффициент сглаживания для EWMA
    'ewma_k_sigma': 2.5  # k стандартных отклонений для флага аномалии
}

# Конфигурация кеширования
CACHE_CONFIG = {
    'level1_max_records': 10,  # На мониторе пациента
    'level2_max_records': 1000,  # В шлюзе отделения
    'level2_ttl_minutes': 60,  # TTL для уровня 2
    'level3_ttl_minutes': None  # Без TTL для центрального сервера
}

# Конфигурация RBAC
RBAC_ROLES = {
    'doctor': {
        'can_access_assigned': True,
        'can_access_ward': False,
        'can_decrypt': True,
        'can_manage_users': False
    },
    'nurse': {
        'can_access_assigned': False,
        'can_access_ward': True,
        'can_decrypt': True,
        'can_manage_users': False
    },
    'admin': {
        'can_access_assigned': False,
        'can_access_ward': False,
        'can_decrypt': False,
        'can_manage_users': True
    },
    'analyst': {
        'can_access_assigned': False,
        'can_access_ward': False,
        'can_decrypt': False,
        'can_manage_users': False
    }
}

# Конфигурация UEBA
UEBA_CONFIG = {
    'max_patients_per_session': 10,
    'max_accesses_per_hour': 50,
    'working_hours': (6, 22),
    'mass_access_threshold': 15,  # Разных пациентов за T минут
    'mass_access_window_minutes': 10
}

# ============================================================================
# ЛОГИРОВАНИЕ
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# МОДЕЛИ ДАННЫХ
# ============================================================================

@dataclass
class PatientVitals:
    """Жизненные показатели пациента"""
    patient_id: str
    timestamp: datetime
    heart_rate: int          # Пульс (ударов в минуту)
    systolic_bp: int         # Систолическое давление
    diastolic_bp: int        # Диастолическое давление
    oxygen_saturation: float  # SpO2 (%)
    respiratory_rate: int    # Частота дыхания
    heart_rate_spo2: Optional[int] = None  # HR из SpO2 датчика для кросс-валидации

    def to_dict(self):
        return {
            'patient_id': self.patient_id,
            'timestamp': self.timestamp.isoformat(),
            'heart_rate': self.heart_rate,
            'systolic_bp': self.systolic_bp,
            'diastolic_bp': self.diastolic_bp,
            'oxygen_saturation': self.oxygen_saturation,
            'respiratory_rate': self.respiratory_rate,
            'heart_rate_spo2': self.heart_rate_spo2
        }


@dataclass
class IntegrityAlert:
    """Алерт о нарушении целостности"""
    alert_type: str  # 'limits', 'rate_of_change', 'cross_sensor', 'trend'
    patient_id: str
    timestamp: datetime
    severity: str  # 'low', 'medium', 'high', 'critical'
    details: str


@dataclass
class AccessLog:
    """Логирование доступа пользователя (для UEBA)"""
    user_id: str
    timestamp: datetime
    action: str
    patient_ids_accessed: List[str]
    location: str
    is_suspicious: bool = False
    reason: str = ""
    severity: str = "low"
    recommended_action: str = "none"


@dataclass
class User:
    """Пользователь системы"""
    user_id: str
    role: str  # 'doctor', 'nurse', 'admin', 'analyst'
    assigned_patients: List[str] = None
    known_locations: List[str] = None

    def __post_init__(self):
        if self.assigned_patients is None:
            self.assigned_patients = []
        if self.known_locations is None:
            self.known_locations = ['ICU_subnet', '127.0.0.1']


# ============================================================================
# ЦЕЛОСТНОСТЬ (INTEGRITY)
# ============================================================================

class IntegrityValidator:
    """
    ЦЕЛОСТНОСТЬ (Integrity): Обеспечение корректности и достоверности данных
    
    Алгоритмы:
    1. Физиологические лимиты: проверка диапазонов значений (настраиваемые пороги)
    2. Проверка скорости изменения: дельта за минуту (rate-of-change)
    3. Кросс-датчиковая валидация: сравнение HR из ECG vs HR из SpO2 (N последовательных измерений)
    4. Отклонение тренда: вычисление EWMA базовой линии и флаг отклонений за k сигм
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or INTEGRITY_CONFIG
        self.patient_history = {}  # {patient_id: deque of PatientVitals}
        self.patient_ewma = {}  # {patient_id: {metric: (ewma_value, variance)}}
        self.alerts: List[IntegrityAlert] = []
    
    def validate_physical_limits(self, vitals: PatientVitals) -> List[IntegrityAlert]:
        """
        A) Проверка физиологических лимитов (настраиваемые пороги)
        """
        alerts = []
        cfg = self.config
        
        # Пульс >= 250 = ошибка датчика
        if vitals.heart_rate >= cfg['heart_rate_max']:
            alerts.append(IntegrityAlert(
                alert_type='limits',
                patient_id=vitals.patient_id,
                timestamp=vitals.timestamp,
                severity='critical',
                details=f'Пульс {vitals.heart_rate} >= {cfg["heart_rate_max"]} - ошибка датчика'
            ))
        elif vitals.heart_rate < cfg['heart_rate_min']:
            alerts.append(IntegrityAlert(
                alert_type='limits',
                patient_id=vitals.patient_id,
                timestamp=vitals.timestamp,
                severity='high',
                details=f'Пульс {vitals.heart_rate} < {cfg["heart_rate_min"]} - брадикардия'
            ))
        
        # Давление
        if vitals.systolic_bp > cfg['systolic_bp_max']:
            alerts.append(IntegrityAlert(
                alert_type='limits',
                patient_id=vitals.patient_id,
                timestamp=vitals.timestamp,
                severity='critical',
                details=f'Систолическое давление {vitals.systolic_bp} > {cfg["systolic_bp_max"]}'
            ))
        if vitals.diastolic_bp > cfg['diastolic_bp_max']:
            alerts.append(IntegrityAlert(
                alert_type='limits',
                patient_id=vitals.patient_id,
                timestamp=vitals.timestamp,
                severity='critical',
                details=f'Диастолическое давление {vitals.diastolic_bp} > {cfg["diastolic_bp_max"]}'
            ))
        
        # Кислород
        if vitals.oxygen_saturation < cfg['oxygen_saturation_min'] or vitals.oxygen_saturation > cfg['oxygen_saturation_max']:
            alerts.append(IntegrityAlert(
                alert_type='limits',
                patient_id=vitals.patient_id,
                timestamp=vitals.timestamp,
                severity='critical',
                details=f'SpO2 {vitals.oxygen_saturation} вне диапазона [{cfg["oxygen_saturation_min"]}, {cfg["oxygen_saturation_max"]}]'
            ))
        
        return alerts
    
    def validate_rate_of_change(self, vitals: PatientVitals) -> List[IntegrityAlert]:
        """
        B) Проверка скорости изменения (дельта за минуту)
        """
        alerts = []
        patient_id = vitals.patient_id
        cfg = self.config
        
        if patient_id not in self.patient_history:
            self.patient_history[patient_id] = deque(maxlen=10)
        
        history = self.patient_history[patient_id]
        
        if len(history) > 0:
            prev = history[-1]
            time_delta = (vitals.timestamp - prev.timestamp).total_seconds() / 60.0  # минуты
            
            if time_delta > 0:
                # Пульс
                hr_delta = abs(vitals.heart_rate - prev.heart_rate) / time_delta
                if hr_delta > cfg['rate_of_change_hr_threshold']:
                    alerts.append(IntegrityAlert(
                        alert_type='rate_of_change',
                        patient_id=patient_id,
                        timestamp=vitals.timestamp,
                        severity='high',
                        details=f'Скорость изменения пульса {hr_delta:.1f} уд/мин за минуту (порог: {cfg["rate_of_change_hr_threshold"]})'
                    ))
                
                # SpO2
                o2_delta = abs(vitals.oxygen_saturation - prev.oxygen_saturation) / time_delta
                if o2_delta > cfg['rate_of_change_o2_threshold']:
                    alerts.append(IntegrityAlert(
                        alert_type='rate_of_change',
                        patient_id=patient_id,
                        timestamp=vitals.timestamp,
                        severity='high',
                        details=f'Скорость изменения SpO2 {o2_delta:.1f}% за минуту (порог: {cfg["rate_of_change_o2_threshold"]})'
                    ))
                
                # Давление
                bp_delta = abs(vitals.systolic_bp - prev.systolic_bp) / time_delta
                if bp_delta > cfg['rate_of_change_bp_threshold']:
                    alerts.append(IntegrityAlert(
                        alert_type='rate_of_change',
                        patient_id=patient_id,
                        timestamp=vitals.timestamp,
                        severity='medium',
                        details=f'Скорость изменения давления {bp_delta:.1f} мм рт.ст. за минуту (порог: {cfg["rate_of_change_bp_threshold"]})'
                    ))
        
        history.append(vitals)
        return alerts
    
    def validate_cross_sensor(self, vitals: PatientVitals) -> List[IntegrityAlert]:
        """
        C) Кросс-датчиковая валидация: сравнение HR из ECG vs HR из SpO2
        Требуется N последовательных измерений для снижения ложных срабатываний
        """
        alerts = []
        patient_id = vitals.patient_id
        cfg = self.config
        
        if vitals.heart_rate_spo2 is None:
            return alerts  # Нет данных для сравнения
        
        if patient_id not in self.patient_history:
            self.patient_history[patient_id] = deque(maxlen=cfg['cross_sensor_n_samples'] + 5)
        
        history = self.patient_history[patient_id]
        
        # Проверяем последние N измерений
        if len(history) >= cfg['cross_sensor_n_samples']:
            recent = list(history)[-cfg['cross_sensor_n_samples']:]
            disagreements = 0
            
            for prev_vitals in recent:
                if prev_vitals.heart_rate_spo2 is not None:
                    diff = abs(prev_vitals.heart_rate - prev_vitals.heart_rate_spo2)
                    if diff > 10:  # Разница > 10 ударов
                        disagreements += 1
            
            # Если все N измерений показывают расхождение
            if disagreements >= cfg['cross_sensor_n_samples']:
                current_diff = abs(vitals.heart_rate - vitals.heart_rate_spo2)
                alerts.append(IntegrityAlert(
                    alert_type='cross_sensor',
                    patient_id=patient_id,
                    timestamp=vitals.timestamp,
                    severity='high',
                    details=f'Расхождение HR ECG ({vitals.heart_rate}) vs SpO2 ({vitals.heart_rate_spo2}) в {cfg["cross_sensor_n_samples"]} последовательных измерениях. Текущая разница: {current_diff}'
                ))
        
        return alerts
    
    def validate_trend_deviation(self, vitals: PatientVitals) -> List[IntegrityAlert]:
        """
        D) Отклонение тренда: вычисление EWMA базовой линии и флаг отклонений за k сигм
        """
        alerts = []
        patient_id = vitals.patient_id
        cfg = self.config
        alpha = cfg['ewma_alpha']
        k_sigma = cfg['ewma_k_sigma']
        
        if patient_id not in self.patient_ewma:
            self.patient_ewma[patient_id] = {
                'heart_rate': (vitals.heart_rate, 0.0),
                'oxygen_saturation': (vitals.oxygen_saturation, 0.0),
                'systolic_bp': (vitals.systolic_bp, 0.0)
            }
            return alerts
        
        ewma_state = self.patient_ewma[patient_id]
        
        # Обновление EWMA для каждого показателя
        metrics = [
            ('heart_rate', vitals.heart_rate),
            ('oxygen_saturation', vitals.oxygen_saturation),
            ('systolic_bp', vitals.systolic_bp)
        ]
        
        for metric_name, current_value in metrics:
            ewma_prev, variance_prev = ewma_state[metric_name]
            
            # Обновление EWMA
            ewma_new = alpha * current_value + (1 - alpha) * ewma_prev
            
            # Обновление дисперсии (упрощенная версия)
            error = current_value - ewma_prev
            variance_new = alpha * (error ** 2) + (1 - alpha) * variance_prev
            std_dev = variance_new ** 0.5 if variance_new > 0 else 1.0
            
            # Проверка отклонения
            deviation = abs(current_value - ewma_prev)
            if deviation > k_sigma * std_dev and std_dev > 0:
                alerts.append(IntegrityAlert(
                    alert_type='trend',
                    patient_id=patient_id,
                    timestamp=vitals.timestamp,
                    severity='medium',
                    details=f'{metric_name}: отклонение {deviation:.2f} > {k_sigma} сигм (EWMA: {ewma_prev:.2f}, текущее: {current_value:.2f}, сигма: {std_dev:.2f})'
                ))
            
            ewma_state[metric_name] = (ewma_new, variance_new)
        
        return alerts
    
    def validate_all(self, vitals: PatientVitals) -> List[IntegrityAlert]:
        """Полная валидация данных - возвращает список алертов"""
        all_alerts = []
        
        all_alerts.extend(self.validate_physical_limits(vitals))
        all_alerts.extend(self.validate_rate_of_change(vitals))
        all_alerts.extend(self.validate_cross_sensor(vitals))
        all_alerts.extend(self.validate_trend_deviation(vitals))
        
        # Сохраняем алерты
        self.alerts.extend(all_alerts)
        
        return all_alerts


# ============================================================================
# ДОСТУПНОСТЬ (AVAILABILITY)
# ============================================================================

class CacheEntry:
    """Запись в кеше с временной меткой"""
    def __init__(self, vitals: PatientVitals):
        self.vitals = vitals
        self.timestamp = datetime.now()
        self.access_time = datetime.now()  # Для LRU


class MultiLevelCache:
    """
    ДОСТУПНОСТЬ (Availability): Многоуровневое кеширование с TTL и LRU
    
    Архитектура:
    - L1: Кеш на мониторе пациента (последние значения, маленький)
    - L2: Кеш в шлюзе отделения (окно последних X минут, TTL)
    - L3: Центральный сервер (полная история)
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or CACHE_CONFIG
        # L1: {patient_id: deque(maxlen=10)}
        self.level1_cache = {}
        # L2: OrderedDict для LRU, с проверкой TTL
        self.level2_cache = OrderedDict()
        # L3: список записей
        self.level3_cache = []
        self.central_server_alive = True
        # История для графиков: [(timestamp, l1_count, l2_count, l3_count)]
        self.history = []
    
    def write(self, vitals: PatientVitals):
        """Запись данных во все уровни кеша"""
        entry = CacheEntry(vitals)
        
        # L1: Кеш на мониторе
        if vitals.patient_id not in self.level1_cache:
            self.level1_cache[vitals.patient_id] = deque(maxlen=self.config['level1_max_records'])
        self.level1_cache[vitals.patient_id].append(entry)
        
        # L2: Кеш в отделении (LRU)
        key = f"{vitals.patient_id}_{vitals.timestamp.isoformat()}"
        self.level2_cache[key] = entry
        # Перемещаем в конец (самый свежий)
        self.level2_cache.move_to_end(key)
        # Ограничение размера
        while len(self.level2_cache) > self.config['level2_max_records']:
            self.level2_cache.popitem(last=False)  # Удаляем самый старый
        
        # L3: Центральный сервер (если живой)
        if self.central_server_alive:
            self.level3_cache.append(entry)
        
        # Записываем статистику для графиков
        self._record_stats()
    
    def _record_stats(self):
        """Запись статистики для графиков"""
        l1_count = sum(len(v) for v in self.level1_cache.values())
        l2_count = len(self.level2_cache)
        l3_count = len(self.level3_cache)
        self.history.append((datetime.now(), l1_count, l2_count, l3_count))
    
    def read(self, patient_id: str) -> Optional[PatientVitals]:
        """Чтение данных с приоритетом L1 -> L2 -> L3"""
        # L1
        if patient_id in self.level1_cache:
            cache = list(self.level1_cache[patient_id])
            if cache:
                cache[-1].access_time = datetime.now()  # Обновляем LRU
                return cache[-1].vitals
        
        # L2 (с проверкой TTL)
        ttl_minutes = self.config['level2_ttl_minutes']
        now = datetime.now()
        for key, entry in reversed(self.level2_cache.items()):  # С конца (самые свежие)
            if entry.vitals.patient_id == patient_id:
                if ttl_minutes is None or (now - entry.timestamp).total_seconds() / 60 < ttl_minutes:
                    entry.access_time = now
                    self.level2_cache.move_to_end(key)  # Обновляем LRU
                    return entry.vitals
        
        # L3
        for entry in reversed(self.level3_cache):  # С конца
            if entry.vitals.patient_id == patient_id:
                return entry.vitals
        
        return None
    
    def simulate_server_failure(self):
        """Имитация падения центрального сервера"""
        self.central_server_alive = False
        logger.error("СИМУЛЯЦИЯ: Центральный сервер упал!")
        self._record_stats()
    
    def simulate_server_recovery(self):
        """Имитация восстановления сервера"""
        self.central_server_alive = True
        logger.info("Центральный сервер восстановлен")
        self._record_stats()
    
    def get_cache_stats(self) -> Dict:
        """Статистика кешей"""
        return {
            'level1_patients': len(self.level1_cache),
            'level1_total_records': sum(len(v) for v in self.level1_cache.values()),
            'level2_records': len(self.level2_cache),
            'level3_records': len(self.level3_cache),
            'central_server_alive': self.central_server_alive
        }


# ============================================================================
# КОНФИДЕНЦИАЛЬНОСТЬ (CONFIDENTIALITY) - RBAC и UEBA
# ============================================================================

class ConfidentialityManager:
    """
    КОНФИДЕНЦИАЛЬНОСТЬ (Confidentiality):
    
    Механизмы:
    1. RBAC (Role-Based Access Control): роли и политики доступа
    2. UEBA (User and Entity Behavior Analytics): анализ поведения пользователей
    3. AES-GCM Encryption: реальное шифрование данных
    4. Data Anonymization: анонимизация с SHA-256
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or UEBA_CONFIG
        self.access_logs: List[AccessLog] = []
        self.users: Dict[str, User] = {}
        # Ключи для шифрования (в реальности должны быть в безопасном хранилище)
        self.encryption_key = os.urandom(32)  # 256 бит для AES-256
        self.hmac_key = os.urandom(32)
        self.crypto_available = CRYPTOGRAPHY_AVAILABLE
        
        if not self.crypto_available:
            logger.warning("Библиотека cryptography не установлена. Шифрование отключено.")
            logger.warning("Установите: pip install cryptography")
    
    def add_user(self, user: User):
        """Добавление пользователя в систему"""
        self.users[user.user_id] = user
    
    def authorize(self, user_id: str, patient_id: str, action: str) -> Tuple[bool, str]:
        """
        RBAC: авторизация доступа пользователя к данным пациента
        
        Политики:
        - doctor: доступ к назначенным пациентам
        - nurse: доступ к пациентам отделения
        - admin: управление пользователями, но не может читать медицинские данные по умолчанию
        - analyst: доступ только к анонимизированным данным, не может расшифровать личные записи
        """
        if user_id not in self.users:
            return False, f"Пользователь {user_id} не найден"
        
        user = self.users[user_id]
        role_config = RBAC_ROLES.get(user.role)
        
        if role_config is None:
            return False, f"Неизвестная роль: {user.role}"
        
        # Admin может управлять пользователями, но не читать медицинские данные
        if user.role == 'admin' and action in ['view', 'read']:
            return False, "Администратор не может читать медицинские данные пациентов"
        
        # Analyst может только анонимизированные данные
        if user.role == 'analyst' and action in ['view', 'read', 'decrypt']:
            return False, "Аналитик может работать только с анонимизированными данными"
        
        # Doctor: доступ к назначенным пациентам
        if user.role == 'doctor':
            if role_config['can_access_assigned']:
                if patient_id in user.assigned_patients:
                    return True, "Доступ разрешен: пациент назначен врачу"
                else:
                    return False, f"Врач не имеет доступа к пациенту {patient_id}"
        
        # Nurse: доступ к пациентам отделения
        if user.role == 'nurse':
            if role_config['can_access_ward']:
                return True, "Доступ разрешен: медсестра имеет доступ к отделению"
        
        return False, f"Доступ запрещен для роли {user.role} и действия {action}"
    
    def analyze_user_behavior(self, user_id: str, accessed_patients: List[str], 
                            timestamp: datetime, location: str) -> Tuple[bool, Optional[str], str, str]:
        """
        UEBA-lite: анализ поведения пользователя
        
        Проверки:
        - Массовый доступ: много разных пациентов за T минут
        - Необычное время: вне рабочего времени
        - Необычное место: место не в списке известных мест пользователя
        
        Возвращает: (is_normal, reason, severity, recommended_action)
        """
        cfg = self.config
        
        # Проверка 1: Массовый доступ
        window_start = timestamp - timedelta(minutes=cfg['mass_access_window_minutes'])
        recent_accesses = [
            log for log in self.access_logs
            if log.user_id == user_id and log.timestamp >= window_start
        ]
        
        distinct_patients = set()
        for log in recent_accesses:
            distinct_patients.update(log.patient_ids_accessed)
        
        if len(distinct_patients) >= cfg['mass_access_threshold']:
            return False, f"Массовый доступ: {len(distinct_patients)} разных пациентов за {cfg['mass_access_window_minutes']} минут", "high", "block"
        
        # Проверка 2: Необычное место
        if user_id in self.users:
            user = self.users[user_id]
            if location not in user.known_locations:
                return False, f"Доступ из неизвестного места: {location}", "medium", "step_up_auth"
        
        # Проверка 3: Необычное время
        hour = timestamp.hour
        if not (cfg['working_hours'][0] <= hour < cfg['working_hours'][1]):
            return False, f"Доступ в нерабочее время: {hour}:00", "low", "notify"
        
        return True, None, "low", "none"
    
    def encrypt_record(self, record_dict: Dict, key_bytes: bytes = None) -> bytes:
        """
        Шифрование записи с использованием AES-GCM
        
        Если cryptography недоступна, выбрасывает исключение с понятным сообщением
        """
        if not self.crypto_available:
            raise RuntimeError("Шифрование требует установки библиотеки cryptography. Установите: pip install cryptography")
        
        if key_bytes is None:
            key_bytes = self.encryption_key
        
        # Сериализация в JSON
        data = json.dumps(record_dict, sort_keys=True).encode('utf-8')
        
        # AES-GCM шифрование
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12)  # 96 бит для GCM
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Объединяем nonce и ciphertext
        return nonce + ciphertext
    
    def decrypt_record(self, token_bytes: bytes, key_bytes: bytes = None) -> Dict:
        """Расшифровка записи"""
        if not self.crypto_available:
            raise RuntimeError("Расшифровка требует установки библиотеки cryptography")
        
        if key_bytes is None:
            key_bytes = self.encryption_key
        
        # Извлекаем nonce и ciphertext
        nonce = token_bytes[:12]
        ciphertext = token_bytes[12:]
        
        # Расшифровка
        aesgcm = AESGCM(key_bytes)
        data = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Десериализация
        return json.loads(data.decode('utf-8'))
    
    def sign_record(self, record_dict: Dict, hmac_key_bytes: bytes = None) -> str:
        """Подпись записи с использованием HMAC-SHA256"""
        if hmac_key_bytes is None:
            hmac_key_bytes = self.hmac_key
        
        data = json.dumps(record_dict, sort_keys=True).encode('utf-8')
        signature = hmac.new(hmac_key_bytes, data, hashlib.sha256).hexdigest()
        return signature
    
    def verify_signature(self, record_dict: Dict, signature_hex: str, hmac_key_bytes: bytes = None) -> bool:
        """Проверка подписи"""
        if hmac_key_bytes is None:
            hmac_key_bytes = self.hmac_key
        
        expected_signature = self.sign_record(record_dict, hmac_key_bytes)
        return hmac.compare_digest(signature_hex, expected_signature)
    
    def pseudonymize_patient_id(self, patient_id: str, salt: bytes = None) -> str:
        """Псевдонимизация ID пациента с использованием SHA-256 с солью"""
        if salt is None:
            salt = b'default_salt_2025'  # В реальности должна быть уникальная соль
        
        data = (patient_id + salt.hex()).encode('utf-8')
        hash_obj = hashlib.sha256(data)
        return 'ANON_' + hash_obj.hexdigest()[:16]
    
    def anonymize_records(self, records: List[Dict], salt: bytes = None) -> List[Dict]:
        """
        Анонимизация списка записей
        
        Удаляет прямые идентификаторы и заменяет patient_id на псевдоним
        """
        anonymized = []
        for record in records:
            anon_record = record.copy()
            # Удаляем прямые идентификаторы (если есть)
            for key in ['name', 'insurance', 'address', 'phone']:
                anon_record.pop(key, None)
            # Псевдонимизируем patient_id
            if 'patient_id' in anon_record:
                anon_record['patient_id'] = self.pseudonymize_patient_id(anon_record['patient_id'], salt)
            anonymized.append(anon_record)
        return anonymized
    
    def log_access(self, user_id: str, accessed_patients: List[str], 
                  timestamp: datetime, location: str, action: str = 'view'):
        """Логирование доступа для аудита и UEBA"""
        is_normal, reason, severity, recommended_action = self.analyze_user_behavior(
            user_id, accessed_patients, timestamp, location
        )
        
        log = AccessLog(
            user_id=user_id,
            timestamp=timestamp,
            action=action,
            patient_ids_accessed=accessed_patients,
            location=location,
            is_suspicious=not is_normal,
            reason=reason or "Нормальный доступ",
            severity=severity,
            recommended_action=recommended_action
        )
        self.access_logs.append(log)
        
        if not is_normal:
            logger.warning(f"UEBA АЛЕРТ: {reason} (severity: {severity}, action: {recommended_action})")
    
    def export_access_logs_to_csv(self, filename: str):
        """Экспорт логов доступа в CSV"""
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['user_id', 'timestamp', 'action', 'patient_ids', 'location', 'is_suspicious', 'severity', 'recommended_action', 'reason'])
            for log in self.access_logs:
                writer.writerow([
                    log.user_id,
                    log.timestamp.isoformat(),
                    log.action,
                    ','.join(log.patient_ids_accessed),
                    log.location,
                    log.is_suspicious,
                    log.severity,
                    log.recommended_action,
                    log.reason
                ])


# ============================================================================
# ИНТЕГРИРОВАННАЯ СИСТЕМА МОНИТОРИНГА
# ============================================================================

class PatientMonitoringSystem:
    """
    Полная система мониторинга пациентов в реанимации с триадой CIA
    """
    
    def __init__(self):
        self.integrity_validator = IntegrityValidator()
        self.cache_manager = MultiLevelCache()
        self.confidentiality_manager = ConfidentialityManager()
        self.all_integrity_alerts = []
    
    def process_patient_data(self, vitals: PatientVitals, user_id: str, location: str,
                           user_role: str = 'doctor', assigned_patients: List[str] = None) -> Dict:
        """
        Основной процесс обработки данных пациента с проверкой RBAC
        """
        result = {
            'timestamp': vitals.timestamp,
            'patient_id': vitals.patient_id,
            'vitals': vitals.to_dict(),
            'integrity_alerts': [],
            'confidentiality_check': {},
            'availability_status': {}
        }
        
        # ========== RBAC: Проверка авторизации ==========
        if user_id not in self.confidentiality_manager.users:
            # Создаем пользователя на лету для демо
            user = User(user_id=user_id, role=user_role, assigned_patients=assigned_patients or [])
            self.confidentiality_manager.add_user(user)
        
        allowed, reason = self.confidentiality_manager.authorize(user_id, vitals.patient_id, 'view')
        if not allowed:
            result['confidentiality_check'] = {
                'access_denied': True,
                'reason': reason
            }
            logger.error(f"Доступ запрещен: {reason}")
            return result
        
        # ========== 1. ЦЕЛОСТНОСТЬ ==========
        integrity_alerts = self.integrity_validator.validate_all(vitals)
        result['integrity_alerts'] = [asdict(alert) for alert in integrity_alerts]
        self.all_integrity_alerts.extend(integrity_alerts)
        
        if integrity_alerts:
            logger.warning(f"Обнаружены алерты целостности: {len(integrity_alerts)}")
            for alert in integrity_alerts:
                logger.warning(f"  [{alert.severity}] {alert.alert_type}: {alert.details}")
        
        # Сохраняем в кеш только если нет критических ошибок
        critical_errors = [a for a in integrity_alerts if a.severity == 'critical']
        if not critical_errors:
            self.cache_manager.write(vitals)
        else:
            logger.error("Данные не сохранены из-за критических ошибок целостности")
        
        # ========== 2. ДОСТУПНОСТЬ ==========
        cache_stats = self.cache_manager.get_cache_stats()
        result['availability_status'] = cache_stats
        
        # ========== 3. КОНФИДЕНЦИАЛЬНОСТЬ ==========
        # Шифрование данных
        try:
            encrypted_token = self.confidentiality_manager.encrypt_record(vitals.to_dict())
            result['confidentiality_check']['encrypted'] = True
            result['confidentiality_check']['encryption_size'] = len(encrypted_token)
        except RuntimeError as e:
            logger.warning(f"Шифрование недоступно: {e}")
            result['confidentiality_check']['encrypted'] = False
            result['confidentiality_check']['encryption_error'] = str(e)
        
        # Подпись HMAC
        signature = self.confidentiality_manager.sign_record(vitals.to_dict())
        result['confidentiality_check']['signed'] = True
        result['confidentiality_check']['signature'] = signature[:16] + '...'  # Первые 16 символов
        
        # Логирование доступа
        self.confidentiality_manager.log_access(
            user_id=user_id,
            accessed_patients=[vitals.patient_id],
            timestamp=vitals.timestamp,
            location=location,
            action='view_vitals'
        )
        
        result['confidentiality_check']['access_allowed'] = True
        
        return result
    
    def get_system_report(self) -> Dict:
        """Полный отчет о состоянии системы"""
        return {
            'timestamp': datetime.now().isoformat(),
            'cache_stats': self.cache_manager.get_cache_stats(),
            'integrity_alerts_count': len(self.all_integrity_alerts),
            'integrity_alerts_by_type': self._count_alerts_by_type(),
            'access_logs_count': len(self.confidentiality_manager.access_logs),
            'suspicious_accesses': sum(1 for log in self.confidentiality_manager.access_logs if log.is_suspicious),
            'central_server_alive': self.cache_manager.central_server_alive
        }
    
    def _count_alerts_by_type(self) -> Dict[str, int]:
        """Подсчет алертов по типам"""
        counts = {'limits': 0, 'rate_of_change': 0, 'cross_sensor': 0, 'trend': 0}
        for alert in self.all_integrity_alerts:
            counts[alert.alert_type] = counts.get(alert.alert_type, 0) + 1
        return counts


# ============================================================================
# ДЕМОНСТРАЦИЯ И ГРАФИКИ
# ============================================================================

def generate_synthetic_vitals(patient_id: str, base_time: datetime, step: int,
                              inject_anomalies: bool = False) -> PatientVitals:
    """Генерация синтетических жизненных показателей"""
    # Базовые значения для разных пациентов
    baselines = {
        'PAT_001': {'hr': 75, 'bp_sys': 120, 'bp_dia': 80, 'o2': 98.0, 'rr': 16},
        'PAT_002': {'hr': 85, 'bp_sys': 130, 'bp_dia': 85, 'o2': 96.0, 'rr': 18},
        'PAT_003': {'hr': 70, 'bp_sys': 115, 'bp_dia': 75, 'o2': 99.0, 'rr': 14}
    }
    
    baseline = baselines.get(patient_id, baselines['PAT_001'])
    
    # Добавляем реалистичный шум
    noise_hr = random.randint(-3, 3)
    noise_bp = random.randint(-5, 5)
    noise_o2 = random.uniform(-0.5, 0.5)
    noise_rr = random.randint(-1, 1)
    
    # Инжекция аномалий для демонстрации
    hr_spo2_offset = random.randint(-2, 2)  # По умолчанию небольшое расхождение
    
    if inject_anomalies:
        if patient_id == 'PAT_003' and step == 25:
            # Скачок пульса
            noise_hr = 60
        elif patient_id == 'PAT_003' and step == 40:
            # Скачок давления
            noise_bp = 40
        elif patient_id == 'PAT_001' and 30 <= step <= 34:
            # Расхождение HR ECG vs SpO2
            hr_spo2_offset = 25
    
    hr = max(40, baseline['hr'] + noise_hr)
    bp_sys = max(80, baseline['bp_sys'] + noise_bp)
    bp_dia = max(40, baseline['bp_dia'] + noise_bp // 2)
    o2 = max(85.0, min(100.0, baseline['o2'] + noise_o2))
    rr = max(8, baseline['rr'] + noise_rr)
    hr_spo2 = hr + hr_spo2_offset
    
    # Ошибка датчика для PAT_002 на шаге 15
    if patient_id == 'PAT_002' and step == 15:
        hr = 260  # Невозможное значение
    
    return PatientVitals(
        patient_id=patient_id,
        timestamp=base_time + timedelta(minutes=step),
        heart_rate=hr,
        systolic_bp=bp_sys,
        diastolic_bp=bp_dia,
        oxygen_saturation=o2,
        respiratory_rate=rr,
        heart_rate_spo2=hr_spo2
    )


def run_full_demo_and_save_figures() -> Tuple[List[str], Dict]:
    """
    Полная демонстрация системы с генерацией графиков
    
    Возвращает: (список путей к PNG файлам, словарь с итоговой статистикой)
    """
    if not MATPLOTLIB_AVAILABLE:
        logger.warning("Matplotlib не установлен. Графики не могут быть созданы.")
        logger.warning("Установите: pip install matplotlib")
        matplotlib_available = False
    else:
        matplotlib_available = True
        # Создаем папку для графиков
        os.makedirs('результаты', exist_ok=True)
    
    print("\n" + "="*80)
    print(" ПОЛНАЯ ДЕМОНСТРАЦИЯ СИСТЕМЫ МОНИТОРИНГА ".center(80))
    print("="*80)
    
    # Инициализация системы
    system = PatientMonitoringSystem()
    
    # Создаем пользователей
    doctor = User(user_id='DR_IVANOV', role='doctor', assigned_patients=['PAT_001', 'PAT_003'])
    nurse = User(user_id='NURSE_PETROVA', role='nurse', known_locations=['ICU_subnet', '127.0.0.1'])
    suspicious_user = User(user_id='SUSPICIOUS_USER', role='doctor', assigned_patients=[],
                          known_locations=['UNKNOWN_IP'])
    
    system.confidentiality_manager.add_user(doctor)
    system.confidentiality_manager.add_user(nurse)
    system.confidentiality_manager.add_user(suspicious_user)
    
    # Генерация синтетических данных
    base_time = datetime.now()
    patient_ids = ['PAT_001', 'PAT_002', 'PAT_003']
    all_vitals = []
    
    print("\nГенерация синтетических данных для 3 пациентов (60 временных шагов)...")
    
    for step in range(60):
        for patient_id in patient_ids:
            inject_anomalies = (step >= 20)  # Инжектируем аномалии после шага 20
            vitals = generate_synthetic_vitals(patient_id, base_time, step, inject_anomalies)
            all_vitals.append(vitals)
            
            # Обработка данных
            if patient_id in ['PAT_001', 'PAT_003']:
                user_id = 'DR_IVANOV'
                location = '127.0.0.1'
            else:
                user_id = 'NURSE_PETROVA'
                location = 'ICU_subnet'
            
            system.process_patient_data(vitals, user_id, location, 'doctor', ['PAT_001', 'PAT_003'])
    
    # Симуляция падения сервера
    print("\nСимуляция падения центрального сервера на шаге 30...")
    if len(all_vitals) > 30:
        system.cache_manager.simulate_server_failure()
    
    # Продолжаем обработку после падения сервера
    for step in range(60, 80):
        for patient_id in patient_ids[:2]:  # Только 2 пациента продолжают
            vitals = generate_synthetic_vitals(patient_id, base_time, step, False)
            all_vitals.append(vitals)
            system.process_patient_data(vitals, 'DR_IVANOV', '127.0.0.1', 'doctor', ['PAT_001', 'PAT_003'])
    
    # Восстановление сервера
    print("Восстановление центрального сервера на шаге 80...")
    system.cache_manager.simulate_server_recovery()
    
    # Генерация подозрительных доступов
    print("\nГенерация подозрительных доступов...")
    suspicious_times = [
        base_time + timedelta(hours=2),  # Нерабочее время
        base_time + timedelta(hours=3),
        base_time + timedelta(hours=23),  # Ночное время
    ]
    
    for i, sus_time in enumerate(suspicious_times):
        # Массовый доступ
        accessed_patients = [f'PAT_{j:03d}' for j in range(1, 20)]  # 19 пациентов
        system.confidentiality_manager.log_access(
            'SUSPICIOUS_USER', accessed_patients, sus_time, 'UNKNOWN_IP', 'view'
        )
    
    # Нормальные доступы врача
    normal_times = [base_time + timedelta(hours=h) for h in range(8, 18, 2)]
    for norm_time in normal_times:
        system.confidentiality_manager.log_access(
            'DR_IVANOV', ['PAT_001'], norm_time, '127.0.0.1', 'view'
        )
    
    # ========== СОЗДАНИЕ ГРАФИКОВ ==========
    figure_paths = []
    
    if matplotlib_available:
        print("\nСоздание графиков...")
        
        # График 1: Тренд пульса для PAT_003 с отметками аномалий
        pat003_vitals = [v for v in all_vitals if v.patient_id == 'PAT_003']
        pat003_alerts = [a for a in system.all_integrity_alerts if a.patient_id == 'PAT_003']
        
        if pat003_vitals:
            fig, ax = plt.subplots(figsize=(12, 6))
            times = [v.timestamp for v in pat003_vitals]
            heart_rates = [v.heart_rate for v in pat003_vitals]
            
            ax.plot(times, heart_rates, 'b-', label='Пульс (уд/мин)', linewidth=2)
            
            # Отмечаем аномалии
            alert_times = [a.timestamp for a in pat003_alerts]
            alert_hrs = []
            for alert_time in alert_times:
                for v in pat003_vitals:
                    if abs((v.timestamp - alert_time).total_seconds()) < 60:
                        alert_hrs.append(v.heart_rate)
                        break
            
            if alert_times and alert_hrs:
                ax.scatter(alert_times[:len(alert_hrs)], alert_hrs, color='red', s=100, 
                          marker='X', label='Алерты целостности', zorder=5)
            
            ax.set_xlabel('Время', fontsize=12)
            ax.set_ylabel('Пульс (уд/мин)', fontsize=12)
            ax.set_title('Тренд пульса пациента PAT_003 с отметками аномалий', fontsize=14, fontweight='bold')
            ax.legend()
            ax.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            path = 'результаты/fig1_vitals_trend_PAT003.png'
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close()
            figure_paths.append(path)
            print(f"  Сохранен: {path}")
        
        # График 2: Количество алертов по типам
        alert_counts = system._count_alerts_by_type()
        if any(alert_counts.values()):
            fig, ax = plt.subplots(figsize=(10, 6))
            types = list(alert_counts.keys())
            counts = list(alert_counts.values())
            colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#f9ca24']
            
            bars = ax.bar(types, counts, color=colors[:len(types)], alpha=0.7, edgecolor='black', linewidth=1.5)
            ax.set_xlabel('Тип алерта', fontsize=12)
            ax.set_ylabel('Количество', fontsize=12)
            ax.set_title('Количество алертов целостности по типам', fontsize=14, fontweight='bold')
            ax.grid(True, alpha=0.3, axis='y')
            
            # Добавляем значения на столбцы
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{int(height)}', ha='center', va='bottom', fontsize=11, fontweight='bold')
            
            plt.tight_layout()
            path = 'результаты/fig2_integrity_alert_counts.png'
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close()
            figure_paths.append(path)
            print(f"  Сохранен: {path}")
        
        # График 3: Кеши по уровням во времени
        if system.cache_manager.history:
            fig, ax = plt.subplots(figsize=(12, 6))
            times = [h[0] for h in system.cache_manager.history]
            l1_counts = [h[1] for h in system.cache_manager.history]
            l2_counts = [h[2] for h in system.cache_manager.history]
            l3_counts = [h[3] for h in system.cache_manager.history]
            
            ax.plot(times, l1_counts, 'g-', label='L1 (Монитор пациента)', linewidth=2, marker='o', markersize=4)
            ax.plot(times, l2_counts, 'b-', label='L2 (Шлюз отделения)', linewidth=2, marker='s', markersize=4)
            ax.plot(times, l3_counts, 'r-', label='L3 (Центральный сервер)', linewidth=2, marker='^', markersize=4)
            
            # Отмечаем падение и восстановление сервера
            if len(times) > 30:
                server_down_time = times[30]
                ax.axvline(x=server_down_time, color='red', linestyle='--', linewidth=2, label='Сервер упал')
            if len(times) > 80:
                server_up_time = times[80]
                ax.axvline(x=server_up_time, color='green', linestyle='--', linewidth=2, label='Сервер восстановлен')
            
            ax.set_xlabel('Время', fontsize=12)
            ax.set_ylabel('Количество записей', fontsize=12)
            ax.set_title('Количество записей в кешах по уровням во времени', fontsize=14, fontweight='bold')
            ax.legend()
            ax.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            path = 'результаты/fig3_cache_levels_over_time.png'
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close()
            figure_paths.append(path)
            print(f"  Сохранен: {path}")
        
        # График 4: Доступы по часам (нормальный врач vs подозрительный пользователь)
        doctor_logs = [log for log in system.confidentiality_manager.access_logs if log.user_id == 'DR_IVANOV']
        suspicious_logs = [log for log in system.confidentiality_manager.access_logs if log.user_id == 'SUSPICIOUS_USER']
        
        if doctor_logs or suspicious_logs:
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # Подсчет по часам
            doctor_hours = {}
            suspicious_hours = {}
            
            for log in doctor_logs:
                hour = log.timestamp.hour
                doctor_hours[hour] = doctor_hours.get(hour, 0) + 1
            
            for log in suspicious_logs:
                hour = log.timestamp.hour
                suspicious_hours[hour] = suspicious_hours.get(hour, 0) + 1
            
            all_hours = sorted(set(list(doctor_hours.keys()) + list(suspicious_hours.keys())))
            doctor_counts = [doctor_hours.get(h, 0) for h in all_hours]
            suspicious_counts = [suspicious_hours.get(h, 0) for h in all_hours]
            
            x = range(len(all_hours))
            width = 0.35
            
            ax.bar([i - width/2 for i in x], doctor_counts, width, label='Врач (норма)', color='#2ecc71', alpha=0.7)
            ax.bar([i + width/2 for i in x], suspicious_counts, width, label='Подозрительный пользователь', color='#e74c3c', alpha=0.7)
            
            ax.set_xlabel('Час дня', fontsize=12)
            ax.set_ylabel('Количество доступов', fontsize=12)
            ax.set_title('Доступы по часам: нормальный врач vs подозрительный пользователь', fontsize=14, fontweight='bold')
            ax.set_xticks(x)
            ax.set_xticklabels([f'{h}:00' for h in all_hours])
            ax.legend()
            ax.grid(True, alpha=0.3, axis='y')
            plt.tight_layout()
            
            path = 'результаты/fig4_accesses_per_hour.png'
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close()
            figure_paths.append(path)
            print(f"  Сохранен: {path}")
        
        # График 5: Массовый доступ (разные пациенты в окне времени)
        if suspicious_logs:
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # Вычисляем скользящее окно для каждого доступа
            window_minutes = UEBA_CONFIG['mass_access_window_minutes']
            distinct_counts = []
            times_for_plot = []
            
            for i, log in enumerate(suspicious_logs):
                window_start = log.timestamp - timedelta(minutes=window_minutes)
                recent_logs = [
                    l for l in suspicious_logs[:i+1]
                    if l.timestamp >= window_start
                ]
                distinct_patients = set()
                for l in recent_logs:
                    distinct_patients.update(l.patient_ids_accessed)
                distinct_counts.append(len(distinct_patients))
                times_for_plot.append(log.timestamp)
            
            ax.plot(times_for_plot, distinct_counts, 'r-o', linewidth=2, markersize=8, label='Разных пациентов в окне')
            ax.axhline(y=UEBA_CONFIG['mass_access_threshold'], color='red', linestyle='--', 
                      linewidth=2, label=f'Порог массового доступа ({UEBA_CONFIG["mass_access_threshold"]})')
            
            ax.set_xlabel('Время', fontsize=12)
            ax.set_ylabel('Количество разных пациентов', fontsize=12)
            ax.set_title('Массовый доступ: количество разных пациентов в скользящем окне', fontsize=14, fontweight='bold')
            ax.legend()
            ax.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            path = 'результаты/fig5_distinct_patients_burst.png'
            plt.savefig(path, dpi=150, bbox_inches='tight')
            plt.close()
            figure_paths.append(path)
            print(f"  Сохранен: {path}")
    
    # Итоговая статистика
    report = system.get_system_report()
    
    summary = {
        'figure_paths': figure_paths,
        'integrity_alerts_total': report['integrity_alerts_count'],
        'integrity_alerts_by_type': report['integrity_alerts_by_type'],
        'ueba_alerts': report['suspicious_accesses'],
        'total_accesses': report['access_logs_count'],
        'cache_stats': report['cache_stats']
    }
    
    return figure_paths, summary


# ============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================================

def main():
    """
    Главная функция: запуск полной демонстрации с графиками
    """
    print("\n" + "="*80)
    print(" СИСТЕМА МОНИТОРИНГА ПАЦИЕНТОВ В РЕАНИМАЦИИ С ИИ ".center(80))
    print(" Информационная безопасность интеллектуальных систем ".center(80))
    print("="*80)
    print("\nТриада безопасности CIA:")
    print("   C - КОНФИДЕНЦИАЛЬНОСТЬ: RBAC, UEBA, AES-GCM шифрование, анонимизация")
    print("   I - ЦЕЛОСТНОСТЬ: валидация датчиков, кросс-датчиковый анализ, тренды, EWMA")
    print("   A - ДОСТУПНОСТЬ: многоуровневое кеширование с TTL и LRU (3 уровня)\n")
    
    # Запуск полной демонстрации
    figure_paths, summary = run_full_demo_and_save_figures()
    
    # Вывод итоговой статистики
    print("\n" + "="*80)
    print(" ИТОГОВАЯ СТАТИСТИКА ".center(80))
    print("="*80)
    
    print(f"\nАлерты целостности:")
    print(f"   Всего: {summary['integrity_alerts_total']}")
    print(f"   По типам:")
    for alert_type, count in summary['integrity_alerts_by_type'].items():
        print(f"     - {alert_type}: {count}")
    
    print(f"\nUEBA алерты:")
    print(f"   Подозрительных доступов: {summary['ueba_alerts']}")
    print(f"   Всего доступов: {summary['total_accesses']}")
    
    print(f"\nКеширование:")
    cache_stats = summary['cache_stats']
    print(f"   L1 (монитор): {cache_stats['level1_total_records']} записей, {cache_stats['level1_patients']} пациентов")
    print(f"   L2 (шлюз): {cache_stats['level2_records']} записей")
    print(f"   L3 (сервер): {cache_stats['level3_records']} записей")
    print(f"   Статус сервера: {'ЖИВОЙ' if cache_stats['central_server_alive'] else 'МЕРТВЫЙ'}")
    
    print(f"\nГрафики сохранены:")
    for path in figure_paths:
        if os.path.exists(path):
            print(f"   {path}")
        else:
            print(f"   {path} (ОШИБКА: файл не найден)")
    
    print("\n" + "="*80)
    print("\nДЕМОНСТРАЦИЯ ЗАВЕРШЕНА\n")
    print("Вывод:")
    print("   Интеграция ИИ в систему управления инцидентами ИБ позволяет:")
    print("   • Обнаруживать ошибки датчиков в реальном времени (ЦЕЛОСТНОСТЬ)")
    print("   • Продолжать работу при падении сервера (ДОСТУПНОСТЬ)")
    print("   • Выявлять подозрительный доступ автоматически (КОНФИДЕНЦИАЛЬНОСТЬ)")
    print("   • Обеспечивать ролевой доступ к данным (RBAC)")
    print("   • Шифровать данные с использованием AES-GCM")
    print("\n" + "="*80 + "\n")


if __name__ == '__main__':
    main()
