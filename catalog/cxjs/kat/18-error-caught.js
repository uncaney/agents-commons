try { JSON.parse('{bad') } catch (e) { print(e.name, e instanceof SyntaxError) }
try { null.prop } catch (e) { print(e.name) }
class AppError extends Error { constructor(m, code) { super(m); this.name = 'AppError'; this.code = code } }
try { throw new AppError('boom', 42) } catch (e) { print(e.name, e.message, e.code, e instanceof Error, String(e)) }
