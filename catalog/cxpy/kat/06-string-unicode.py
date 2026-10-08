s = "héllo wörld ß 😀"
print(len(s), len(s.encode("utf-8")), s.upper(), s.encode("utf-8")[:3], ascii(s[:5]))
print("😀".encode("utf-8").hex(), hex(ord("😀")), "\U0001F600" == "😀", "é".encode("utf-16-be").hex())
print("naïve café".encode("ascii", "ignore"), "xéy".encode("ascii", "backslashreplace"), b"h\xc3\xa9".decode("utf-8"))
print("日本語".isalpha(), "١٢٣".isdigit(), int("١٢٣"), "½".isnumeric(), "ǅ".lower(), "ΣΊΣΥΦΟΣ".lower(), "ﬁ".upper())
