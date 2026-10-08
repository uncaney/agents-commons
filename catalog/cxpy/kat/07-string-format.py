rows = [("apple", 1.5, 3), ("kiwi", 0.25, 12), ("melon", 3, 1)]
for name, price, qty in rows:
    print(f"{name:<8}{price:>7.2f}{qty:>4d}")
print(f"total {sum(p * q for _, p, q in rows):.2f}")
print("%-5s|%5s|%05d|%+d|%%|%.3e" % ("ab", "cd", 42, 7, 12345.678), "{0} {1} {0}".format("a", "b"), "{x!r} {y:08.3f}".format(x="q", y=3.14159))
print(repr("tab\tq\"uote\n"), str(b"bytes"), f"{1e6:,.0f} {0.256:.1%} {255:#x} {42:>+8} {'c':^5}|")
t = "The quick brown Fox"
print(t.replace("o", "0"), t.startswith("The"), "abc".ljust(6, "-"), "  trim me  ".strip() + "|", "x" * 5, "abc".center(7, "."), "a-b-c".split("-"), chr(72) + chr(105), "Straße".casefold())
