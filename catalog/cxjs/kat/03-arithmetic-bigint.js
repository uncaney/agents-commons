const big = 2n ** 100n;
print(big, big % 1000000007n, (big * big).toString().length);
let f = 1n; for (let i = 1n; i <= 30n; i++) f *= i;
print("30!", f, typeof f, BigInt.asUintN(8, 257n), BigInt("12345678901234567890") + 1n);
