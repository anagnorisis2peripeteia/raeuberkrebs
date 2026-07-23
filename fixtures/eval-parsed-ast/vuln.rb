# PLANTED LEAD (CWE-95, eval of parsed-AST source text): a manifest parser locates an assignment node
# and re-`eval`s its VERBATIM source range — the "safe-looking extractor that re-evals parsed source"
# footgun. The value is attacker-controlled document text (this file also PARSES the input), not a
# constant, so the eval executes arbitrary code — and it sits BEFORE the sanitizer meant to make that
# content safe. The fix is to extract the value STATICALLY (a string-literal node -> its unescaped
# value; anything dynamic -> nil), never eval. Intentional — the eval-of-parsed-AST static lane
# surfaces this as a high-priority lead (parser present).
require "prism"

def extract_value(source)
  ast = Prism.parse(source)
  assign = ast.value.statements.body.first
  # BUG: re-evaluates the raw source text of the parsed node
  eval(assign.slice)
end
