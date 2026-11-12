'use strict';
/* Static, bounded TypeScript/JavaScript AST indexer. Never eval or import target code.
 * Invocation: node web_ts_flow_parser.cjs /ABS/PINNED/typescript.js
 * Data (source files) comes from a bounded JSON envelope on stdin.
 */
const fs = require('fs');
const ts = require(process.argv[2]);
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
if (!payload || !Array.isArray(payload.files) || payload.files.length > 120)
  throw Error('invalid/oversized static source envelope');

const METHODS = new Set(['get', 'post', 'patch', 'put', 'delete']);
const NEXT_METHODS = new Set(['GET', 'POST', 'PATCH', 'PUT', 'DELETE']);
const entries = [];

function callee(e) {
  if (!e) return '';
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) return callee(e.expression) + '.' + e.name.text;
  if (ts.isElementAccessExpression(e) && ts.isStringLiteral(e.argumentExpression))
    return callee(e.expression) + '.' + e.argumentExpression.text;
  return '';
}
function ids(node) {
  const result = new Set();
  function visit(n) {
    if (ts.isIdentifier(n)) result.add(n.text);
    ts.forEachChild(n, visit);
  }
  if (node) visit(node);
  return [...result].sort().slice(0, 30);
}
function location(sf, n) {
  return sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
}
function sourceKind(path) {
  const p = path.toLowerCase();
  if (p.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (p.endsWith('.jsx') || p.endsWith('.js') || p.endsWith('.mjs') || p.endsWith('.cjs'))
    return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}
function safePath(raw) {
  if (typeof raw !== 'string' || raw.length > 420 || !raw.startsWith('/') ||
      raw.startsWith('//') || /[\x00-\x1f\\?#]/.test(raw)) return null;
  return raw.split('/').map(x => x.length > 29 ? '{opaque}' : x).join('/');
}
function nextPath(filename) {
  const m = filename.match(/(?:^|\/)(?:src\/)?app\/(.+)\/route\.[cm]?[jt]sx?$/);
  if (!m) return null;
  return '/' + m[1].split('/').filter(x => x && !/^\(.+\)$/.test(x))
    .map(x => /^\[.+\]$/.test(x) ? '{' + x.slice(1, -1) + '}' : x).join('/');
}
function isExport(node) {
  return !!(node.modifiers && node.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
}
function dangerousHtmlValue(attr) {
  // `dangerouslySetInnerHTML={{__html: value}}`: find the `__html` property's value.
  if (!attr.initializer || !ts.isJsxExpression(attr.initializer) || !attr.initializer.expression)
    return null;
  const obj = attr.initializer.expression;
  if (!ts.isObjectLiteralExpression(obj)) return null;
  for (const prop of obj.properties) {
    if (ts.isPropertyAssignment(prop) &&
        ((ts.isIdentifier(prop.name) && prop.name.text === '__html') ||
         (ts.isStringLiteral(prop.name) && prop.name.text === '__html')))
      return prop.initializer;
  }
  return null;
}
function parseFunction(sf, name, node, exported) {
  const params = node.parameters
    ? [...node.parameters].map(x => ts.isIdentifier(x.name) ? x.name.text : '')
    : [];
  const calls = [], aliases = [];
  const body = node.body || node;
  function visit(n) {
    // Avoid assigning descendants of nested callbacks to an enclosing handler:
    // an inline callback is its own function, but direct callback bodies are examined.
    if (ts.isCallExpression(n)) {
      const c = callee(n.expression);
      if (c && calls.length < 150)
        calls.push({callee: c, line: location(sf, n),
          args: [...n.arguments].slice(0, 15).map(arg => ids(arg))});
    }
    // `new Function(payload)` / `new SomeSink(payload)`: same sink-argument shape as a call.
    if (ts.isNewExpression(n)) {
      const c = callee(n.expression);
      if (c && calls.length < 150)
        calls.push({callee: c, line: location(sf, n),
          args: (n.arguments ? [...n.arguments] : []).slice(0, 15).map(arg => ids(arg))});
    }
    // `el.innerHTML = value` / `location.href = value`: a property write is not a call, but
    // DOM-sink assignment is syntactically identical in shape to a one-argument sink call.
    if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(n.left)) {
      const c = callee(n.left);
      if (c && calls.length < 150)
        calls.push({callee: c, line: location(sf, n), args: [ids(n.right)]});
    }
    if (ts.isJsxAttribute(n) && ts.isIdentifier(n.name) &&
        n.name.text === 'dangerouslySetInnerHTML') {
      const html = dangerousHtmlValue(n);
      if (html && calls.length < 150)
        calls.push({callee: 'dangerouslySetInnerHTML', line: location(sf, n), args: [ids(html)]});
    }
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) &&
        n.initializer && aliases.length < 100) {
      aliases.push({name:n.name.text, from:ids(n.initializer)});
    }
    ts.forEachChild(n, visit);
  }
  visit(body);
  return {name, line:location(sf, node), params, calls, aliases, exported:!!exported};
}
for (const file of payload.files) {
  if (typeof file.path !== 'string' || typeof file.content !== 'string' ||
      file.content.length > 200000) throw Error('invalid bounded source entry');
  const sf = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest,
                                 true, sourceKind(file.path));
  const imports = [], functions = [], routes = [];
  const path = nextPath(file.path);
  for (const st of sf.statements) {
    if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
      const spec = st.moduleSpecifier.text;
      const clause = st.importClause;
      if (!clause) continue;
      const names = [];
      if (clause.name) names.push({local:clause.name.text, exported:'default'});
      if (clause.namedBindings && ts.isNamedImports(clause.namedBindings))
        for (const el of clause.namedBindings.elements)
          names.push({local:el.name.text,
                      exported:el.propertyName ? el.propertyName.text : el.name.text});
      imports.push({specifier:spec, names});
    } else if (ts.isFunctionDeclaration(st) && st.name) {
      functions.push(parseFunction(sf, st.name.text, st, isExport(st)));
      if (path && isExport(st) && NEXT_METHODS.has(st.name.text))
        routes.push({method:st.name.text, path, handler:st.name.text,
                     middleware:[], line:location(sf, st)});
    } else if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !d.initializer) continue;
        const val = d.initializer, name = d.name.text;
        if (ts.isArrowFunction(val) || ts.isFunctionExpression(val))
          functions.push(parseFunction(sf, name, val, isExport(st)));
        if (path && isExport(st) && NEXT_METHODS.has(name) &&
            (ts.isArrowFunction(val) || ts.isFunctionExpression(val)))
          routes.push({method:name, path, handler:name, middleware:[],
                       line:location(sf, d)});
      }
    }
  }
  // Static Express / Fastify-style route handlers.
  function walk(n) {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) &&
        n.arguments.length >= 2) {
      const method = n.expression.name.text.toLowerCase();
      const parent = callee(n.expression.expression);
      const a = n.arguments[0];
      const pathValue = (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a))
        ? safePath(a.text) : null;
      if (METHODS.has(method) && pathValue &&
          /(?:^|\.)(?:app|router|server|fastify)$/.test(parent)) {
        const args = [...n.arguments].slice(1);
        const last = args[args.length - 1];
        let handler = callee(last);
        if (!handler && (ts.isArrowFunction(last) || ts.isFunctionExpression(last))) {
          handler = '__inline_route_' + location(sf, last);
          functions.push(parseFunction(sf, handler, last, false));
        }
        routes.push({method:method.toUpperCase(), path:pathValue, handler,
                     middleware:args.slice(0, -1).map(callee).filter(Boolean).slice(0, 30),
                     line:location(sf, n)});
      }
    }
    ts.forEachChild(n, walk);
  }
  walk(sf);
  entries.push({path:file.path, imports, functions, routes,
                parse_diagnostics:sf.parseDiagnostics.length});
}
process.stdout.write(JSON.stringify({schema_version:1, files:entries}));
