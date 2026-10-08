// cx-wasm-opt: wasm binary on stdin -> optimized wasm binary on stdout, binaryen library on
// wasm32-wasi (SPEC-v2 15.4). Fixed configuration (the sandbox passes no argv): default
// optimization passes at optimizeLevel 2 / shrinkLevel 1 (wasm-opt -Os), debug info dropped,
// default feature set. Read/parse failures end in `err ...` on stdout, exit 1 (see cxa_stubs.cc).
#include <cstdio>
#include <string>
#include <vector>

#include "pass.h"
#include "support/file.h"
#include "wasm-io.h"
#include "wasm.h"

int main() {
  std::vector<char> input = wasm::read_stdin();
  if (input.empty()) {
    fputs("err empty input\n", stdout);
    return 1;
  }
  wasm::Module module;
  wasm::ModuleReader reader;
  reader.setDebugInfo(false);
  reader.readBinaryData(input, module, "");
  wasm::PassRunner runner(&module);
  runner.options.optimizeLevel = 2;
  runner.options.shrinkLevel = 1;
  runner.options.debugInfo = false;
  runner.addDefaultOptimizationPasses();
  runner.run();
  wasm::ModuleWriter writer;
  writer.setBinary(true);
  writer.setDebugInfo(false);
  writer.writeBinary(module, "-");
  fflush(stdout);
  return 0;
}
