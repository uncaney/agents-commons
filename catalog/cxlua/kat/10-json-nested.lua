local function enc(v, out)
  local t = type(v)
  if t == "nil" then out[#out + 1] = "null"
  elseif t == "boolean" then out[#out + 1] = tostring(v)
  elseif t == "number" then out[#out + 1] = math.type(v) == "integer" and tostring(v) or string.format("%.14g", v)
  elseif t == "string" then
    out[#out + 1] = '"' .. v:gsub('[%c"\\]', function(c)
      local m = { ['"'] = '\\"', ["\\"] = "\\\\", ["\n"] = "\\n", ["\t"] = "\\t", ["\r"] = "\\r" }
      return m[c] or string.format("\\u%04x", c:byte()) end) .. '"'
  elseif #v > 0 or next(v) == nil then
    out[#out + 1] = "["
    for i, x in ipairs(v) do if i > 1 then out[#out + 1] = "," end enc(x, out) end
    out[#out + 1] = "]"
  else
    local keys = {}
    for k in pairs(v) do keys[#keys + 1] = tostring(k) end
    table.sort(keys)
    out[#out + 1] = "{"
    for i, k in ipairs(keys) do
      if i > 1 then out[#out + 1] = "," end
      enc(k, out) out[#out + 1] = ":" enc(v[k], out)
    end
    out[#out + 1] = "}"
  end
  return out
end
local function json(v) return table.concat(enc(v, {})) end
local function decode(s)
  local pos = 1
  local val
  local function ws() pos = s:find("%S", pos) or #s + 1 end
  local function str()
    local out = {}
    pos = pos + 1
    while true do
      local c = s:sub(pos, pos)
      if c == '"' then pos = pos + 1 return table.concat(out) end
      if c == "\\" then
        local e = s:sub(pos + 1, pos + 1)
        local m = { n = "\n", t = "\t", r = "\r", b = "\b", f = "\f", ['"'] = '"', ["\\"] = "\\", ["/"] = "/" }
        if e == "u" then out[#out + 1] = utf8.char(tonumber(s:sub(pos + 2, pos + 5), 16)) pos = pos + 6
        else out[#out + 1] = m[e] pos = pos + 2 end
      else out[#out + 1] = c pos = pos + 1 end
    end
  end
  function val()
    ws()
    local c = s:sub(pos, pos)
    if c == "{" then
      local t = {} pos = pos + 1 ws()
      if s:sub(pos, pos) == "}" then pos = pos + 1 return t end
      while true do
        ws() local k = str() ws() pos = pos + 1 t[k] = val() ws()
        local d = s:sub(pos, pos) pos = pos + 1
        if d == "}" then return t end
      end
    elseif c == "[" then
      local t = {} pos = pos + 1 ws()
      if s:sub(pos, pos) == "]" then pos = pos + 1 return t end
      while true do
        t[#t + 1] = val() ws()
        local d = s:sub(pos, pos) pos = pos + 1
        if d == "]" then return t end
      end
    elseif c == '"' then return str()
    elseif s:sub(pos, pos + 3) == "true" then pos = pos + 4 return true
    elseif s:sub(pos, pos + 4) == "false" then pos = pos + 5 return false
    elseif s:sub(pos, pos + 3) == "null" then pos = pos + 4 return nil
    else
      local num = s:match("^-?%d+%.?%d*[eE]?[-+]?%d*", pos)
      pos = pos + #num
      return tonumber(num)
    end
  end
  return val()
end
local data = decode('{"users":[{"id":2,"name":"b","tags":["x"]},{"id":1,"name":"a","tags":[]}],"meta":{"count":2,"ok":true,"none":null},"s":"h\\u00e9\\n"}')
table.sort(data.users, function(p, q) return p.id < q.id end)
local names = {}
for _, u in ipairs(data.users) do names[#names + 1] = u.name end
print(table.concat(names), data.meta.count, data.meta.ok, data.meta.none, data.s, #data.users[2].tags)
print(json(data))
print(json({ 1, 2, 3 }), json({}), json("é\n\"q\""), json(2.5), json(-0.0 + 0), json({ z = 1, a = { x = false } }))
