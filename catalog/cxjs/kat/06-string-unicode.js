const s = "héllo wörld ß 😀";
print(s.length, [...s].length, s.toUpperCase());
print(encodeURIComponent("é ß"), decodeURIComponent("%F0%9F%98%80"), "😀".codePointAt(0).toString(16));
print("ﬁ".normalize("NFKD"), "é".normalize("NFD").length, "é".normalize("NFC") === "é", "é" === "é");
print(JSON.stringify("héllo 😀"), "😀".split("").length, Array.from("añb").join("|"), "ß".localeCompare === undefined);
