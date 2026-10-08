import re
m = re.match(r"due (?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})", "due 2026-03-09")
print(m["year"], m.group("month"), m.groupdict()["day"], m.start("year"))
print(" ".join(f"{k}:{len(v)}" for k, v in re.findall(r"(\w)=(\d+)", "a=1, b=22, c=333")), re.search(r"(?<=\$)\d+", "cost $42").group(), bool(re.search(r"\bfoo\b", "a foo b")))
print(re.sub(r"a*?", "-", "aaa"), re.sub(r"(?:)", ".", "abc"), re.match(r"(a)|(b)", "b").groups(), re.compile(r"(?i)x").flags & re.I != 0)
print(re.findall(r"(\d)(\d)?", "123"), re.escape("a.b*c"), [m.span() for m in re.finditer(r"\d+", "a1bb22ccc333")])
print([int(x) for x in re.match(r"(\d+)-(\d+)-(\d+)", "2026-01-15").groups()], bool(re.fullmatch(r"\d{3}-\d{4}", "5550100")))
