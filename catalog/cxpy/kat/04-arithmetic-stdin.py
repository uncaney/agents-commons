import sys
nums = [float(t) for t in sys.stdin.read().split()]
total = sum(nums)
print("n", len(nums), "sum", total, "mean", f"{total / len(nums):.3f}", "max", max(nums))
print("sorted", ",".join(str(int(n)) if n.is_integer() else str(n) for n in sorted(nums)))
