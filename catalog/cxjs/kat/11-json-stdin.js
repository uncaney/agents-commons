const input = JSON.parse(stdin);
const total = input.items.reduce((a, it) => a + it.qty * it.price, 0);
const byCat = {};
for (const it of input.items) byCat[it.cat] = (byCat[it.cat] || 0) + it.qty;
print(JSON.stringify({ customer: input.customer, total: Math.round(total * 100) / 100, byCat, n: input.items.length }));
