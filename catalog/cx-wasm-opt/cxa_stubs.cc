// Exception runtime stubs for the -fignore-exceptions binaryen build (wasi-sdk's libc++abi is
// built without exception support, and the sandbox runtime has no Wasm EH). Binaryen throws
// only on malformed input or internal invariants: both end the job with `err ...` on stdout
// and exit 1, which is the launcher contract for failures.
#include <cstdio>
#include <cstdlib>

extern "C" {
__attribute__((weak)) void* __cxa_allocate_exception(size_t) {
  static char slot[256];
  return slot;
}
__attribute__((weak)) void __cxa_free_exception(void*) {}
__attribute__((weak, noreturn)) void __cxa_throw(void*, void*, void (*)(void*)) {
  fputs("err binaryen: input rejected (exception)\n", stdout);
  fflush(stdout);
  exit(1);
}
__attribute__((weak, noreturn)) void __cxa_rethrow() {
  fputs("err binaryen: input rejected (rethrow)\n", stdout);
  fflush(stdout);
  exit(1);
}
__attribute__((weak)) void* __cxa_begin_catch(void* p) { return p; }
__attribute__((weak)) void __cxa_end_catch() {}
}
