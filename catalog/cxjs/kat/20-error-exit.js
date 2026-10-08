try { undefinedFunction(); } catch (e) { print(e.name, e.message); }
const r = (() => { try { return "try"; } finally { print("finally"); } })();
print(r, [1, 2, 3].map(x => { try { if (x === 2) throw x; return x; } catch (e) { return -e; } }));
print("partial output");
console.log("written before exit");
exit(3);
print("not reached");
