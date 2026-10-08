local text = 'Contact: ada@example.com, linus@kernel.org; phone +44 20 7946 0958.'
for m in text:gmatch('[%w%.]+@[%w%.]+%.%a+') do io.write(m, ' ') end
print(('555-0100'):match('^%d%d%d%-%d%d%d%d$') ~= nil, text:find('phone'))
print(text:match('(%+%d+) (%d+) (%d+) (%d+)'))
print(('2026-01-15'):match('(%d+)-(%d+)-(%d+)'), ('COLOR'):lower():match('colou?r') ~= nil)
