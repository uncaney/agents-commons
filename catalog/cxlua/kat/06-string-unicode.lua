local s = "héllo wörld ß 😀"
print(#s, utf8.len(s), utf8.codepoint(s, 1), utf8.char(233, 128512))
for p, c in utf8.codes("hé😀") do io.write(p, ":", c, " ") end
print()
print(utf8.offset(s, 3), s:sub(utf8.offset(s, 2), utf8.offset(s, 3) - 1), utf8.len("\xff") == nil)
print(("é"):byte(1, -1))
