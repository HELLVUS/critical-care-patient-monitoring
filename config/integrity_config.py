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