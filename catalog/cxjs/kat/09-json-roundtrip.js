const obj = { name: 'cx', n: 3, ok: true, none: null, list: [1, 'two', 3.5], nested: { a: [{ b: 1 }] } }
const s = JSON.stringify(obj), back = JSON.parse(s)
print(s)
print(back.nested.a[0].b, back.list.length, Object.keys(back).join(','), JSON.stringify(back) === s)
