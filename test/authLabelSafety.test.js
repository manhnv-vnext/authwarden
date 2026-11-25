import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { runScan } from '../src/index.js';

// A security tool must never call an open route "protected". Every case here
// was reproduced against v1.8.0 by an independent review or by scanning real projects.

async function scan(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-safe-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
    return await runScan(dir, {});
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const L = (...l) => l.join('\n') + '\n';
const count = (r, id) => r.findings.filter(f => f.ruleId === id).length;
const auth = (r, p) => r.routes.find(x => x.path === p)?.auth;
const ADMIN = "app.delete('/admin/users/:id', (req, res) => { db.del(req.params.id); res.end(); });";

// ───────── Express ─────────

test('Express: the word "auth" inside a string argument is not a guard', async () => {
  const r = await scan({ 'src/app.js': L("app.use(cors({ origin: 'https://auth.example.com' }));", ADMIN) });
  assert.equal(auth(r, '/admin/users/:id'), 'unprotected');
  assert.equal(count(r, 'AUTH-001'), 1);
});

test('Express: csrf, upload and session-touching code are not authentication', async () => {
  const r = await scan({ 'src/app.js': L(
    "app.post('/admin/export', csrfProtection, exportAll);",
    "app.post('/admin/photo', upload.single('authorPhoto'), savePhoto);",
    "app.get('/admin/seen', (req, res) => { req.session.lastSeen = Date.now(); res.json(all()); });",
    "app.get('/admin/quota', (req, res) => { if (over()) return res.status(403).end(); res.json(all()); });"
  ) });
  assert.equal(count(r, 'AUTH-001'), 4);
});

test('Express: a regex literal containing "/*" does not hide the routes after it', async () => {
  const r = await scan({ 'src/server.js': L("const base = process.env.BASE.replace(/\\/*$/, '');", ADMIN) });
  assert.equal(r.routes.length, 1);
  assert.equal(count(r, 'AUTH-001'), 1);
});

test('Express: a commented-out guard after a backtick regex is still a comment', async () => {
  const r = await scan({ 'src/server.js': L("const s = v.replace(/`/g, '');", '// app.use(requireAuth);', ADMIN) });
  assert.equal(auth(r, '/admin/users/:id'), 'unprotected');
});

test('Express: a router mounted both publicly and behind auth is not protected', async () => {
  const r = await scan({
    'src/index.js': L("const adminRouter = require('./adminRoutes');", "app.use('/public-mirror', adminRouter);", "app.use('/secure', requireAuth, adminRouter);"),
    'src/adminRoutes.js': L('const router = express.Router();', "router.get('/admin/users', listUsers);", 'module.exports = router;')
  });
  assert.equal(auth(r, '/admin/users'), 'unprotected');
});

test('Express route detection does not run on Python files', async () => {
  const r = await scan({ 'api/items.py': L('router = APIRouter(prefix="/items")', '', '@router.get("/", response_model=ItemsPublic)', 'def read_items(session: SessionDep, current_user: CurrentUser) -> Any:', '    return []') });
  assert.deepEqual(r.routes.map(x => `${x.framework} ${x.path} ${x.auth}`), ['FastAPI /items/ protected']);
});

// ───────── FastAPI ─────────

test('FastAPI: words in the path, comments or body do not count as a dependency', async () => {
  const r = await scan({ 'main.py': L(
    'app = FastAPI()',
    '',
    '@app.delete("/admin/tokens/{token_id}")',
    'def revoke(token_id: int, db = Depends(get_db)):',
    '    return db.delete(token_id)',
    '',
    '@app.delete("/admin/users/{user_id}")',
    'def remove(user_id: int, session: SessionDep):',
    '    # TODO: add authentication',
    '    return session.delete(user_id)',
    '',
    '@app.get("/admin/me")',
    'def me(user: User = Depends(get_current_user)):',
    '    return user'
  ) });
  assert.equal(auth(r, '/admin/tokens/{token_id}'), 'unprotected');
  assert.equal(auth(r, '/admin/users/{user_id}'), 'unprotected');
  assert.equal(auth(r, '/admin/me'), 'protected');
  assert.equal(count(r, 'AUTH-001'), 2);
});

test('FastAPI: decorator-level dependencies and annotated dependency types are recognised', async () => {
  const r = await scan({ 'api/users.py': L(
    'router = APIRouter(prefix="/admin")',
    '',
    '@router.get(',
    '    "/users",',
    '    dependencies=[Depends(get_current_active_superuser)],',
    ')',
    'def read_users(session: SessionDep) -> Any:',
    '    return []',
    '',
    '@router.get("/items")',
    'def read_items(session: SessionDep, current_user: CurrentUser) -> Any:',
    '    return []'
  ) });
  assert.equal(auth(r, '/admin/users'), 'protected');
  assert.equal(auth(r, '/admin/items'), 'protected');
  assert.equal(count(r, 'AUTH-001'), 0);
});

// ───────── Next.js ─────────

const nextRoute = (...body) => L('export async function DELETE(req) {', ...body, '  return Response.json({ ok: true });', '}');

test('Next.js: a variable named "author" is not an auth check and handlers do not bleed into each other', async () => {
  const r = await scan({ 'app/api/admin/posts/route.ts': L(
    'export async function DELETE(req) {',
    '  const author = await req.json();',
    '  await db.post.deleteMany({ where: { author } });',
    '  return Response.json({ ok: true });',
    '}',
    '',
    'export async function GET(req) {',
    '  const session = await auth();',
    "  if (!session?.user) return new Response('no', { status: 401 });",
    '  return Response.json(await db.post.findMany());',
    '}'
  ) });
  const byMethod = Object.fromEntries(r.routes.map(x => [x.method, x.auth]));
  assert.deepEqual(byMethod, { DELETE: 'unprotected', GET: 'protected' });
  assert.equal(count(r, 'AUTH-001'), 1);
});

test('Next.js: a middleware that only mentions auth in a comment protects nothing', async () => {
  const r = await scan({
    'middleware.ts': L('// TODO: auth goes here', 'export function middleware(req) { return NextResponse.next(); }'),
    'app/api/admin/wipe/route.ts': nextRoute('  await db.wipe();')
  });
  assert.equal(count(r, 'AUTH-001'), 1);
});

test('Next.js: non-async and const-assigned handlers are discovered', async () => {
  const r = await scan({
    'app/api/admin/wipe/route.ts': L('export function DELETE(req) {', '  return wipe();', '}', '', 'export const POST = async (req) => {', '  return wipe();', '};'),
    'app/api/admin/safe/route.ts': L('export const POST = withAuth(async (req) => {', '  return wipe();', '});')
  });
  assert.equal(r.routes.filter(x => x.path === '/api/admin/wipe').length, 2);
  assert.equal(count(r, 'AUTH-001'), 2);
  assert.equal(auth(r, '/api/admin/safe'), 'protected');
});

// ───────── ASP.NET Core ─────────

const CONTROLLER = (name, route, attrs = '') => L(attrs + '[ApiController]', `[Route("${route}")]`, `public class ${name} : ControllerBase`, '{', '    [HttpDelete("users/{id}")]', '    public IActionResult Remove(int id)', '    {', '        return Ok();', '    }', '}');

test('ASP.NET: a commented-out fallback policy does not protect controllers', async () => {
  const r = await scan({
    'Api/Api.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>\n',
    'Api/Program.cs': L('// options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();', 'app.MapControllers();'),
    'Api/Controllers/AdminController.cs': CONTROLLER('AdminController', 'api/admin')
  });
  assert.equal(auth(r, '/api/admin/users/{id}'), 'unprotected');
  assert.equal(count(r, 'AUTH-001'), 1);
});

test('ASP.NET: a fallback policy in one project does not protect another project', async () => {
  const r = await scan({
    'Secure/Secure.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>\n',
    'Secure/Program.cs': L('o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();'),
    'Open/Open.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>\n',
    'Open/Controllers/AdminController.cs': CONTROLLER('AdminController', 'api/admin')
  });
  assert.equal(auth(r, '/api/admin/users/{id}'), 'unprotected');
});

test('ASP.NET: .AllowAnonymous() after a lambda with statements is honoured', async () => {
  const r = await scan({
    'Program.cs': L(
      'o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();',
      'app.MapPost("/admin/reset", async (Db db) => { await db.ResetAsync(); return Results.Ok(); }).AllowAnonymous();',
      'app.MapPost("/admin/sync", async (Db db) => { await db.SyncAsync(); return Results.Ok(); });'
    )
  });
  assert.equal(auth(r, '/admin/reset'), 'unprotected');
  assert.equal(auth(r, '/admin/sync'), 'protected');
});

test('ASP.NET: each controller class in a file gets its own attributes and route', async () => {
  const r = await scan({ 'Controllers/Both.cs': CONTROLLER('ProfileController', 'api/profile', '[Authorize]\n') + '\n' + CONTROLLER('AdminController', 'api/admin') });
  assert.equal(auth(r, '/api/profile/users/{id}'), 'protected');
  assert.equal(auth(r, '/api/admin/users/{id}'), 'unprotected');
});

test('ASP.NET: endpoints mapped by an extension method that is chained with RequireAuthorization are protected', async () => {
  const r = await scan({
    'Ordering/Ordering.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>\n',
    'Ordering/Program.cs': L('var orders = app.NewVersionedApi("Orders");', 'orders.MapOrdersApiV1()', '      .RequireAuthorization();', 'app.MapCatalogApi();'),
    'Ordering/Apis/OrdersApi.cs': L('public static class OrdersApi', '{', '    public static RouteGroupBuilder MapOrdersApiV1(this IEndpointRouteBuilder app)', '    {', '        var api = app.MapGroup("api/orders");', '        api.MapPost("/draft", CreateOrderDraftAsync);', '        return api;', '    }', '}'),
    'Ordering/Apis/CatalogApi.cs': L('public static class CatalogApi', '{', '    public static IEndpointRouteBuilder MapCatalogApi(this IEndpointRouteBuilder app)', '    {', '        app.MapPost("/items", CreateItem);', '        return app;', '    }', '}')
  });
  assert.equal(auth(r, '/draft'), 'protected');
  assert.equal(auth(r, '/items'), 'unprotected');
  assert.equal(count(r, 'AUTH-002'), 1);
});

// ───────── Spring ─────────

test('Spring: permitAll() matchers are excluded from the global authenticated() rule', async () => {
  const r = await scan({
    'src/main/java/app/SecurityConfig.java': L('public class SecurityConfig {', '  SecurityFilterChain chain(HttpSecurity http) throws Exception {', '    http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").permitAll().anyRequest().authenticated());', '    return http.build();', '  }', '}'),
    'src/main/java/app/AdminController.java': L('@RestController', '@RequestMapping("/admin")', 'public class AdminController {', '    @DeleteMapping("/users/{id}")', '    public void remove(@PathVariable Long id) {', '    }', '}'),
    'src/main/java/app/OrderController.java': L('@RestController', '@RequestMapping("/orders")', 'public class OrderController {', '    @GetMapping("/export")', '    public List<Order> export() {', '        return List.of();', '    }', '}')
  });
  assert.equal(auth(r, '/admin/users/{id}'), 'unprotected');
  assert.equal(auth(r, '/orders/export'), 'protected');
  assert.equal(count(r, 'AUTH-001'), 1);
});

test('Spring: mappings with named attributes and package-private methods are discovered', async () => {
  const r = await scan({ 'src/main/java/app/AdminController.java': L(
    '@RestController', '@RequestMapping("/admin")', 'public class AdminController {',
    '    @GetMapping(value = "/dump", produces = MediaType.APPLICATION_JSON_VALUE)', '    public String dump() {', '        return "";', '    }',
    '    @DeleteMapping("/wipe")', '    void wipe() {', '    }', '}'
  ) });
  assert.deepEqual(r.routes.map(x => x.path).sort(), ['/admin/dump', '/admin/wipe']);
  assert.equal(count(r, 'AUTH-001'), 2);
});

// ───────── AUTH-003 ─────────

test('AUTH-003 does not flag a repository method declaration', async () => {
  const r = await scan({ 'src/main/java/app/OwnerRepository.java': L('public interface OwnerRepository extends Repository<Owner, Integer> {', '    Optional<Owner> findById(Integer id);', '}') });
  assert.equal(count(r, 'AUTH-003'), 0);
});

// ───────── Unknown middleware ─────────

test('unrecognised middleware yields "unknown", and the finding is kept at low confidence', async () => {
  const r = await scan({ 'src/app.js': L("app.post('/admin/export', csrfProtection, exportAll);", "app.get('/admin/open', listAll);") });
  const exportRoute = r.routes.find(x => x.path === '/admin/export');
  assert.equal(exportRoute.auth, 'unknown');
  assert.match(exportRoute.evidence, /csrfProtection/);
  assert.equal(auth(r, '/admin/open'), 'unprotected');
  const findings = r.findings.filter(f => f.ruleId === 'AUTH-001');
  assert.equal(findings.length, 2);
  assert.equal(findings.find(f => /export/.test(f.title)).confidence, 'LOW');
  assert.deepEqual(r.stats.routes, { total: 2, protected: 0, unprotected: 1, unknown: 1 });
});

test('authIdentifiers lets a project name its own auth middleware', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aw-safe-'));
  fs.mkdirSync(path.join(dir, 'src'));
  fs.writeFileSync(path.join(dir, 'src/app.js'), L(
    "app.post('/admin/addresses', security.appendUserId(), createAddress);",
    "app.put('/admin/orders/:id', security.isAccounting(), toggle);",
    "app.post('/admin/other', security.somethingElse(), other);"
  ));
  const r = await runScan(dir, { authIdentifiers: ['appendUserId', 'isAccounting'] });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(auth(r, '/admin/addresses'), 'protected');
  assert.equal(auth(r, '/admin/orders/:id'), 'protected');
  assert.equal(auth(r, '/admin/other'), 'unknown');
  assert.equal(count(r, 'AUTH-001'), 1);
});
