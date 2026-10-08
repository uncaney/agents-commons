local function j(v)
  if type(v) == 'table' then
    local ks, out = {}, {}
    for k in pairs(v) do ks[#ks + 1] = k end
    table.sort(ks, function(x, y) return tostring(x) < tostring(y) end)
    for _, k in ipairs(ks) do out[#out + 1] = (#v > 0 and '' or '"' .. k .. '":') .. j(v[k]) end
    return (#v > 0 and '[' or '{') .. table.concat(out, ',') .. (#v > 0 and ']' or '}')
  end
  return type(v) == 'string' and '"' .. v .. '"' or tostring(v)
end
print(j({ name = 'cx', n = 3, ok = true, list = { 1, 'two', 3.5 }, nested = { a = { { b = 1 } } } }))
