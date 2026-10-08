// cx-wat2wasm: WAT text on stdin -> wasm binary on stdout (wabt library, SPEC-v2 15.4).
// Parse errors are printed on stdout in wabt's "<stdin>:line:col: error: ..." form, exit 1.
// Features: wabt defaults (MVP + the proposals wabt enables by default).
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "wabt/binary-writer.h"
#include "wabt/error-formatter.h"
#include "wabt/feature.h"
#include "wabt/ir.h"
#include "wabt/resolve-names.h"
#include "wabt/stream.h"
#include "wabt/validator.h"
#include "wabt/wast-lexer.h"
#include "wabt/wast-parser.h"

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
  std::vector<uint8_t> src = read_stdin();
  wabt::Features features;
  wabt::Errors errors;
  std::unique_ptr<wabt::WastLexer> lexer =
      wabt::WastLexer::CreateBufferLexer("<stdin>", src.data(), src.size(), &errors);
  std::unique_ptr<wabt::Module> module;
  wabt::WastParseOptions parse_options(features);
  wabt::Result result = wabt::ParseWatModule(lexer.get(), &module, &errors, &parse_options);
  if (wabt::Succeeded(result)) {
    result = wabt::ResolveNamesModule(module.get(), &errors);
  }
  if (wabt::Succeeded(result)) {
    wabt::ValidateOptions options(features);
    result = wabt::ValidateModule(module.get(), &errors, options);
  }
  if (wabt::Failed(result)) {
    auto line_finder = lexer->MakeLineFinder();
    wabt::FormatErrorsToFile(errors, wabt::Location::Type::Text, line_finder.get(), stdout);
    fflush(stdout);
    return 1;
  }
  wabt::MemoryStream stream;
  wabt::WriteBinaryOptions write_options(features, /*canonicalize_lebs=*/true,
                                         /*relocatable=*/false, /*write_debug_names=*/false);
  result = wabt::WriteBinaryModule(&stream, module.get(), write_options);
  if (wabt::Failed(result)) {
    fputs("err write failed\n", stdout);
    return 1;
  }
  const std::vector<uint8_t>& out = stream.output_buffer().data;
  fwrite(out.data(), 1, out.size(), stdout);
  fflush(stdout);
  return 0;
}
