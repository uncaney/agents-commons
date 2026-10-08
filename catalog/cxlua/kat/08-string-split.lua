print(arg[0], #arg, table.concat(arg, "|"))
local csv = "name,age,city\nAda,36,London\nLinus,28,Helsinki"
local head
for line in csv:gmatch("[^\n]+") do
  local f = {}
  for v in line:gmatch("[^,]+") do f[#f + 1] = v end
  if not head then head = f
  else
    local rec = {}
    for i, h in ipairs(head) do rec[h] = f[i] end
    print(rec.city, table.concat(f, " "))
  end
end
local n = 0
for _ in ("one two  three"):gmatch("%S+") do n = n + 1 end
print(n, select("#", ("a,b,,c"):match("(.-),(.-),(.-),(.*)")))
