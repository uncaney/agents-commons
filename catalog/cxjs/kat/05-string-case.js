const s = 'The quick brown Fox'
print(s.toUpperCase(), '|', s.toLowerCase(), '|', s.length, s.indexOf('quick'), s.includes('Fox'), s.at(-1))
print(s.split(' ').map(w => w[0].toUpperCase() + w.slice(1).toLowerCase()).join(' '), 'abc'.padStart(6, '*'), [...'hello'].reverse().join(''))
