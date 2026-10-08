local s = 'The quick brown Fox'
print(s:upper(), '|', s:lower(), '|', #s, s:find('quick'), s:sub(-3), s:reverse())
print((s:gsub('(%a)([%w_]*)', function(a, b) return a:upper() .. b:lower() end)), ('abc'):rep(2, '-'), s:byte(1), string.char(72, 105))
