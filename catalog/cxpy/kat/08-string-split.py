import sys
args = sys.argv[1:]
print(sys.argv[0], len(args), "|".join(args))
csv = "name,age,city\nAda,36,London\nLinus,28,Helsinki"
head, *rows = (line.split(",") for line in csv.split("\n"))
for r in rows:
    rec = dict(zip(head, r))
    print(rec["city"], " ".join(r))
print(len([x for x in "a,b,,c".split(",") if x]), len("one two  three".split()), "a,b,,c".split(",", 1), "k=v=w".partition("="), "x".rsplit("y"))
