// cx-wasm-validate: wasm binary on stdin -> "ok" on stdout (exit 0) or wabt's error lines
// (exit 1). Uses wabt's binary reader + validator with default features (SPEC-v2 15.4).
#include <cstdio>
#include <vector>

#include "wabt/binary-reader-ir.h"
#include "wabt/binary-reader.h"
#include "wabt/error-formatter.h"
#include "wabt/feature.h"
#include "wabt/ir.h"
#include "wabt/validator.h"

static std::vector<uint8_t> read_stdin() {
  std::vector<uint8_t> data;
  uint8_t buf[1 << 16];
  size_t n;
  while ((n = fread(buf, 1, sizeof buf, stdin)) > 0) {
    data.insert(data.end(), buf, buf + n);
    if (data.size() > (64u << 20)) {
      data.clear();
      break;
    }
  }
  return data;
}

int main() {
  std::vector<uint8_t> data = read_stdin();
  if (data.empty()) {
    fputs("err empty input\n", stdout);
    return 1;
  }
  wabt::Features features;
  wabt::Errors errors;
  wabt::Module module;
  wabt::ReadBinaryOptions options(features, /*log_stream=*/nullptr, /*read_debug_names=*/true,
                                  /*stop_on_first_error=*/true,
                                  /*fail_on_custom_section_error=*/true);
  wabt::Result result = wabt::ReadBinaryIr("<stdin>", data.data(), data.size(), options, &errors, &module);
  if (wabt::Succeeded(result)) {
    wabt::ValidateOptions vopts(features);
    result = wabt::ValidateModule(&module, &errors, vopts);
  }
  if (wabt::Failed(result)) {
    wabt::FormatErrorsToFile(errors, wabt::Location::Type::Binary, nullptr, stdout);
    fflush(stdout);
    return 1;
  }
  fputs("ok\n", stdout);
  fflush(stdout);
  return 0;
}
