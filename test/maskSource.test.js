import { test } from 'node:test';
import assert from 'node:assert/strict';
import { maskSource, maskComments } from '../src/utils/fileContext.js';

const js = (src) => maskSource(src, '.js');

test('masking preserves length and line structure', () => {
  const src = "const a = 'x'; // c\n/* b\n b */ const r = /a\\/b/g;\nconst t = `v ${a + '}'} w`;\n";
  const { code, skeleton } = js(src);
  assert.equal(code.length, src.length);
  assert.equal(skeleton.length, src.length);
  assert.equal(code.split('\n').length, src.split('\n').length);
});

test('"/*" inside a regex literal does not start a block comment', () => {
  const src = "const base = env.BASE.replace(/\\/*$/, '');\napp.delete('/admin/users/:id', handler);\n";
  const { code } = js(src);
  assert.ok(code.includes("app.delete('/admin/users/:id', handler);"));
});

test('a backtick inside a regex literal does not open a template string', () => {
  const src = "const s = v.replace(/`/g, '');\n// app.use(requireAuth);\napp.get('/x', h);\n";
  const { code } = js(src);
  assert.equal(code.includes('requireAuth'), false);
  assert.ok(code.includes("app.get('/x', h);"));
});

test('skeleton blanks string contents but keeps code and quotes', () => {
  const { code, skeleton } = js("app.use(cors({ origin: 'https://auth.example.com' })); upload.single(\"authorPhoto\");\n");
  assert.ok(code.includes('auth.example.com'));
  assert.equal(skeleton.includes('auth'), false);
  assert.ok(skeleton.includes('app.use(cors({ origin:'));
  assert.ok(skeleton.includes('upload.single('));
});

test('template literal text is blanked but ${} expressions stay code', () => {
  const { skeleton } = js("const q = `SELECT auth FROM t WHERE id = ${req.params.id} -- '`; next();\n");
  assert.equal(skeleton.includes('SELECT'), false);
  assert.ok(skeleton.includes('req.params.id'));
  assert.ok(skeleton.includes('next();'));
});

test('division is not mistaken for a regex literal', () => {
  const { skeleton } = js('const r = total / count; const s = a / b; // done\nnext();\n');
  assert.ok(skeleton.includes('total / count; const s = a / b;'));
  assert.equal(skeleton.includes('done'), false);
  assert.ok(skeleton.includes('next();'));
});

test('an apostrophe in JSX text does not swallow following lines', () => {
  const { code } = maskSource("return <p>Don't stop</p>;\n// gone\nkeep();\n", '.jsx');
  assert.equal(code.includes('gone'), false);
  assert.ok(code.includes('keep();'));
});

test('URLs in strings and bare text are not comments', () => {
  const { code } = js('const u = "https://x.io/a"; // note\nfetch(u);\n');
  assert.ok(code.includes('https://x.io/a'));
  assert.equal(code.includes('note'), false);
});

test('Python: # in strings is kept, docstrings are strings, comments are removed', () => {
  const src = 'x = "a # b"  # real comment\ndef f():\n    """Doc with auth and # hash\n    second line"""\n    return 1  # tail\n';
  const { code, skeleton } = maskSource(src, '.py');
  assert.ok(code.includes('a # b'));
  assert.equal(code.includes('real comment'), false);
  assert.equal(code.includes('tail'), false);
  assert.ok(code.includes('Doc with auth'));
  assert.equal(skeleton.includes('auth'), false);
  assert.ok(skeleton.includes('return 1'));
});

test('C#: commented-out code is removed and verbatim strings are handled', () => {
  const src = '// options.FallbackPolicy = x.RequireAuthenticatedUser().Build();\nvar p = @"C:\\dir\\";\nvar q = "a"; /* RequireAuthorization */ Run();\n';
  const { code, skeleton } = maskSource(src, '.cs');
  assert.equal(code.includes('FallbackPolicy'), false);
  assert.equal(code.includes('RequireAuthorization'), false);
  assert.ok(skeleton.includes('Run();'));
  assert.ok(skeleton.includes('var q ='));
});

test('maskComments keeps its line-array contract', () => {
  const out = maskComments(['a(); // x', '/* y', 'z */ b();'], '.js');
  assert.equal(out.length, 3);
  assert.equal(out[0].trimEnd(), 'a();');
  assert.equal(out[1].trim(), '');
  assert.equal(out[2].trim(), 'b();');
});
