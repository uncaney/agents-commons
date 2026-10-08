function level2(x) { if (x > 1) throw new RangeError("value " + x + " out of range"); return x; }
function level1(x) { return level2(x * 2); }
print("before");
level1(1);
print("never printed");
