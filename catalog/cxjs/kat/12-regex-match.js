const text = 'Contact: ada@example.com, linus@kernel.org; phone +44 20 7946 0958.'
print(text.match(/[\w.]+@[\w.]+\.\w+/g), /^\d{3}-\d{4}$/.test('555-0100'), text.search(/phone/))
const m = /(\+\d+) (\d+) (\d+) (\d+)/.exec(text)
print(m[0], m.index, m.slice(1).join('|'), /colou?r/i.test('COLOR'))
