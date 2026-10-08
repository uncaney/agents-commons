def level2(x):
    if x > 1:
        raise RuntimeError(f"value {x} out of range")
    return x

def level1(x):
    return level2(x * 2)

print("before")
level1(1)
print("never printed")
