const re = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})/;
const m = "due 2026-03-09".match(re);
print(m.groups.year, m.groups.month, m.groups.day, m.index);
const all = [..."a=1, b=22, c=333".matchAll(/(\w)=(\d+)/g)].map(x => `${x[1]}:${x[2].length}`);
print(all.join(" "), /(?<=\$)\d+/.exec("cost $42")[0], /\bfoo\b/.test("a foo b"), /^[\p{L}]+$/u.test("héllo"));
print("aaa".replace(/a*?/g, "-"), "abc".replace(/(?:)/g, "."), /(a)|(b)/.exec("b").length);
print("2026-01-15".match(/(\d+)-(\d+)-(\d+)/).slice(1).map(Number), /^\d{3}-\d{4}$/.test("5550100"));
