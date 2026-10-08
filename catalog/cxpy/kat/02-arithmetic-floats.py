import math
print(0.1 + 0.2, f"{0.1 + 0.2:.2f}", 1 / 3, 10 / 4, 7 // 2.0)
print(math.sqrt(2), f"{math.pi:.5f}", round(2.5), round(3.5), round(-2.5), math.trunc(-7.9), math.fmod(7, 3))
print(f"{1234.5678:.1f} {0.000001234:.2e} {255:x} {255:b} {3.14159:8.3f}|{42:<5d}|{7:+d}")
print(math.inf, -math.inf, math.isinf(1e308 * 10), math.isclose(0.1 + 0.2, 0.3), math.hypot(3, 4), 1e16 + 1)
print(float("1.5"), repr(1.0), 2.0 == 2, 1e-7, 123456789.123456789, 0.1 * 3)
