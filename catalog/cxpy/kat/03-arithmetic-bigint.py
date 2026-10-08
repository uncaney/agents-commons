import math
from decimal import Decimal, getcontext
from fractions import Fraction
big = 2 ** 100
print(big, big % 1000000007, len(str(big * big)), math.factorial(30))
print(Fraction(1, 3) + Fraction(1, 6), Fraction(355, 113) > math.pi, Fraction("0.75"))
getcontext().prec = 30
print(Decimal(1) / Decimal(7), Decimal("0.1") + Decimal("0.2"), Decimal("1.10") * 3)
print(12345678901234567890 + 1, (1 << 64) - 1, big.bit_length(), math.isqrt(10 ** 20), math.gcd(84, 36), math.lcm(4, 6))
