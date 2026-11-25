import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { runScan } from '../src/index.js';
import { cli } from '../src/cli.js';

function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-routes-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

async function scan(files) {
  const dir = project(files);
  try {
    return await runScan(dir, {});
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const ids = (result, ruleId) => result.findings.filter(f => f.ruleId === ruleId);
const route = (result, p) => result.routes.find(r => r.path === p);

// ---------- Express ----------

test('Express: router.use(auth) protects routes declared after it', async () => {
  const result = await scan({
    'src/admin.js': [
      "const router = express.Router();",
      "router.use(requireAuth);",
      "router.delete('/admin/users/:id', removeUser);"
    ].join('\n')
  });
  assert.equal(ids(result, 'AUTH-001').length, 0);
  const r = route(result, '/admin/users/:id');
  assert.equal(r.method, 'DELETE');
  assert.equal(r.auth, 'protected');
  assert.match(r.evidence, /router\.use/);
});

test('Express: a route declared before router.use(auth) is still flagged', async () => {
  const result = await scan({
    'src/admin.js': [
      "router.delete('/admin/users/:id', removeUser);",
      "router.use(requireAuth);"
    ].join('\n')
  });
  assert.equal(ids(result, 'AUTH-001').length, 1);
  assert.equal(route(result, '/admin/users/:id').auth, 'unprotected');
});

test('Express: path-scoped app.use only protects routes under that prefix', async () => {
  const result = await scan({
    'src/app.js': [
      "app.use('/admin', verifyToken);",
      "app.get('/admin/stats', stats);",
      "app.get('/billing/export', exportAll);"
    ].join('\n')
  });
  const flagged = ids(result, 'AUTH-001');
  assert.equal(flagged.length, 1);
  assert.match(flagged[0].title, /\/billing\/export/);
  assert.equal(route(result, '/admin/stats').auth, 'protected');
});

test('Express: session middleware and router mounts are not treated as auth', async () => {
  const result = await scan({
    'src/app.js': [
      "app.use(session({ secret: process.env.S }));",
      "app.use('/auth', authRouter);",
      "app.get('/admin/stats', stats);"
    ].join('\n')
  });
  assert.equal(ids(result, 'AUTH-001').length, 1);
});

// ---------- Next.js ----------

const NEXT_ROUTE = 'export async function POST(req) {\n  await db.user.deleteMany();\n  return Response.json({ ok: true });\n}\n';

test('Next.js: middleware matcher covering the route suppresses AUTH-001', async () => {
  const result = await scan({
    'middleware.ts': "import { getToken } from 'next-auth/jwt';\nexport async function middleware(req) { const t = await getToken({ req }); if (!t) return Response.redirect('/login'); }\nexport const config = { matcher: ['/api/admin/:path*'] };\n",
    'app/api/admin/users/route.ts': NEXT_ROUTE,
    'app/api/billing/pay/route.ts': NEXT_ROUTE
  });
  const flagged = ids(result, 'AUTH-001');
  assert.equal(flagged.length, 1);
  assert.match(flagged[0].title, /\/api\/billing\/pay/);
  const r = route(result, '/api/admin/users');
  assert.equal(r.auth, 'protected');
  assert.match(r.evidence, /middleware/);
});

test('Next.js: middleware that excludes /api via negative lookahead does not protect API routes', async () => {
  const result = await scan({
    'middleware.ts': "import { auth } from './auth';\nexport default auth;\nexport const config = { matcher: ['/((?!api|_next/static|favicon.ico).*)'] };\n",
    'app/api/admin/users/route.ts': NEXT_ROUTE
  });
  assert.equal(ids(result, 'AUTH-001').length, 1);
});

test('Next.js: middleware without auth logic does not protect routes', async () => {
  const result = await scan({
    'middleware.ts': "export function middleware(req) { return NextResponse.next(); }\n",
    'app/api/admin/users/route.ts': NEXT_ROUTE
  });
  assert.equal(ids(result, 'AUTH-001').length, 1);
});

// ---------- FastAPI ----------

test('FastAPI: router-level dependencies protect its routes', async () => {
  const result = await scan({
    'api/admin.py': [
      'router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])',
      '',
      '@router.get("/stats")',
      'def stats():',
      '    return {}'
    ].join('\n')
  });
  assert.equal(ids(result, 'AUTH-001').length, 0);
  assert.equal(route(result, '/admin/stats').auth, 'protected');
});

test('FastAPI: router prefix is applied when deciding a route is administrative', async () => {
  const result = await scan({
    'api/admin.py': [
      'router = APIRouter(prefix="/admin")',
      '',
      '@router.get("/stats")',
      'def stats(db = Depends(get_db)):',
      '    return {}'
    ].join('\n')
  });
  const flagged = ids(result, 'AUTH-001');
  assert.equal(flagged.length, 1);
  assert.match(flagged[0].title, /\/admin\/stats/);
});

// ---------- ASP.NET Core ----------

const CONTROLLER = [
  'using Microsoft.AspNetCore.Mvc;',
  '[ApiController]',
  '[Route("api/orders")]',
  'public class OrdersController : ControllerBase',
  '{',
  '    [HttpPost]',
  '    public IActionResult Create(CreateOrderRequest request)',
  '    {',
  '        return Ok();',
  '    }',
  '',
  '    [AllowAnonymous]',
  '    [HttpDelete("admin/purge")]',
  '    public IActionResult Purge()',
  '    {',
  '        return Ok();',
  '    }',
  '}'
].join('\n');

test('ASP.NET Core: a global fallback policy protects controllers, [AllowAnonymous] still opts out', async () => {
  const result = await scan({
    'Program.cs': 'builder.Services.AddAuthorization(o => {\n  o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();\n});\n',
    'Controllers/OrdersController.cs': CONTROLLER
  });
  assert.equal(ids(result, 'AUTH-002').filter(f => /POST \/api\/orders$/.test(f.title)).length, 0);
  assert.equal(ids(result, 'AUTH-001').length, 1);
  assert.equal(route(result, '/api/orders').auth, 'protected');
  assert.equal(route(result, '/api/orders/admin/purge').auth, 'unprotected');
});

test('ASP.NET Core: without a global policy the unprotected POST is flagged', async () => {
  const result = await scan({ 'Controllers/OrdersController.cs': CONTROLLER });
  assert.equal(ids(result, 'AUTH-002').filter(f => /POST \/api\/orders$/.test(f.title)).length, 1);
});

// ---------- Spring ----------

const SPRING_CONTROLLER = [
  '@RestController',
  '@RequestMapping("/admin")',
  'public class AdminController {',
  '    @GetMapping("/users")',
  '    public List<User> users() {',
  '        return repo.findAll();',
  '    }',
  '}'
].join('\n');

test('Spring: SecurityFilterChain with anyRequest().authenticated() protects controllers', async () => {
  const result = await scan({
    'src/main/java/app/SecurityConfig.java': 'public class SecurityConfig {\n  SecurityFilterChain chain(HttpSecurity http) throws Exception {\n    http.authorizeHttpRequests(a -> a.anyRequest().authenticated());\n    return http.build();\n  }\n}\n',
    'src/main/java/app/AdminController.java': SPRING_CONTROLLER
  });
  assert.equal(ids(result, 'AUTH-001').length, 0);
  assert.equal(route(result, '/admin/users').auth, 'protected');
});

test('Spring: without a security config the admin endpoint is flagged', async () => {
  const result = await scan({ 'src/main/java/app/AdminController.java': SPRING_CONTROLLER });
  assert.equal(ids(result, 'AUTH-001').length, 1);
});

// ---------- Inventory output ----------

test('scan result exposes a route inventory with counts', async () => {
  const result = await scan({
    'src/app.js': [
      "app.get('/health', ping);",
      "app.post('/orders', requireAuth, createOrder);"
    ].join('\n')
  });
  assert.equal(result.routes.length, 2);
  const order = route(result, '/orders');
  assert.deepEqual(
    { method: order.method, file: order.file, line: order.line, framework: order.framework, auth: order.auth },
    { method: 'POST', file: 'src/app.js', line: 2, framework: 'Express', auth: 'protected' }
  );
  assert.deepEqual(result.stats.routes, { total: 2, protected: 1, unprotected: 1 });
});

test('routes command prints the inventory as JSON', async () => {
  const dir = project({ 'src/app.js': "app.post('/orders', requireAuth, createOrder);\n" });
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  let code;
  try {
    code = await cli(['routes', dir, '--format', 'json']);
  } finally {
    console.log = orig;
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(code, 0);
  const parsed = JSON.parse(lines.join('\n'));
  assert.equal(parsed.routes[0].path, '/orders');
  assert.equal(parsed.summary.total, 1);
});

test('Express: route-looking text inside a string literal is not a route', async () => {
  const result = await scan({
    'src/help.js': [
      "const hint = `Apply a limiter: router.post('/login', authLimiter, handler);`;",
      "const doc = \"Example: app.get('/admin/stats', stats)\";",
      "app.get('/real', handler);"
    ].join('\n')
  });
  assert.deepEqual(result.routes.map(r => r.path), ['/real']);
  assert.equal(ids(result, 'AUTH-001').length, 0);
});

// ---------- Regressions found by scanning OWASP NodeGoat ----------

test('Express: a handler whose name contains "session" or "auth" is not middleware', async () => {
  const result = await scan({
    'src/routes.js': [
      "app.get('/admin/sessions', sessionHandler.listAll);",
      "app.get('/admin/tokens', authController.listTokens);"
    ].join('\n')
  });
  assert.equal(ids(result, 'AUTH-001').length, 2);
  assert.equal(route(result, '/admin/sessions').auth, 'unprotected');
});

test('Express: isLoggedIn-style middleware is recognised', async () => {
  const result = await scan({
    'src/routes.js': [
      "app.get('/admin/stats', isLoggedIn, statsHandler.show);",
      "app.get('/admin/users', ensureLoggedIn('/login'), usersHandler.list);"
    ].join('\n')
  });
  assert.equal(ids(result, 'AUTH-001').length, 0);
  assert.equal(route(result, '/admin/stats').auth, 'protected');
  assert.equal(route(result, '/admin/users').auth, 'protected');
});

test('Express: call-expression middleware and handler wrappers count as auth', async () => {
  const result = await scan({
    'src/routes.js': [
      "app.post('/admin/import', passport.authenticate('jwt', { session: false }), importHandler);",
      "app.get('/admin/export', requireAuth(exportHandler));"
    ].join('\n')
  });
  assert.equal(ids(result, 'AUTH-001').length, 0);
});

test('Express: commented-out routes are not part of the inventory', async () => {
  const result = await scan({
    'src/routes.js': [
      "app.get('/benefits', isLoggedIn, benefits.show);",
      '/* Fix for A7:',
      " app.get('/admin/benefits', isLoggedIn, isAdmin, benefits.show);",
      ' */',
      "// app.delete('/admin/purge', purge);"
    ].join('\n')
  });
  assert.deepEqual(result.routes.map(r => r.path), ['/benefits']);
  assert.equal(ids(result, 'AUTH-001').length, 0);
});

// ---------- Regressions found by scanning OWASP Juice Shop ----------

test('Express: a deny-all or authorisation guard used as the only argument protects the route', async () => {
  const result = await scan({
    'server.ts': [
      "app.delete('/admin/products/:id', security.denyAll())",
      "app.get('/admin/users', security.isAuthorized())",
      "app.get('/admin/version', utils.asyncHandler(retrieveAppVersion()))"
    ].join('\n')
  });
  const flagged = ids(result, 'AUTH-001');
  assert.equal(flagged.length, 1);
  assert.match(flagged[0].title, /\/admin\/version/);
});

test('AUTH-003 ignores lookups keyed by the authenticated user\'s own id', async () => {
  const lookup = 'findBy' + 'Pk';
  const result = await scan({
    'routes/password.ts': [
      'export async function changePassword(req, res) {',
      `  const user = await UserModel.${lookup}(loggedInUser.data.id)`,
      '  res.json(user)',
      '}'
    ].join('\n'),
    'routes/coupon.ts': [
      'export async function applyCoupon(req, res) {',
      '  const id = req.params.id',
      `  const basket = await BasketModel.${lookup}(id)`,
      '  res.json(basket)',
      '}'
    ].join('\n')
  });
  const flagged = ids(result, 'AUTH-003');
  assert.deepEqual(flagged.map(f => f.file), ['routes/coupon.ts']);
});
