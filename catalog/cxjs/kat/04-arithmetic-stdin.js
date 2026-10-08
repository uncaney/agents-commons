const nums = stdin.trim().split(/\s+/).map(Number);
const sum = nums.reduce((a, b) => a + b, 0);
print("n", nums.length, "sum", sum, "mean", (sum / nums.length).toFixed(3), "max", Math.max(...nums));
print("sorted", nums.slice().sort((a, b) => a - b).join(","));
