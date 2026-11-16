/*
 * Conservative Java AST intraprocedural def-use and interfile parameter flow.
 * Operator-provided Java is parsed/analyzed by JDK 17 without running classes,
 * loading application classpath or invoking annotation processors.
 *
 * This is intentionally NOT a complete taint or control-flow analysis.
 * It only handles ordered straight-line assignments and exact Java method
 * symbols. Branches invalidate state rather than create imaginary flows.
 */
import com.sun.source.tree.*;
import com.sun.source.util.*;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import javax.lang.model.element.*;
import javax.tools.*;

public final class MobileCompilerFlow {
    private static final int MAX_FILES = 350;
    private static final int MAX_HOPS = 3;
    private static final int MAX_FLOWS = 120;
    private static final int MAX_VISITS = 12000;
    private static final Set<String> SINK_CUES = Set.of(
        "loadUrl", "loadDataWithBaseURL", "setResult", "openFileOutput",
        "openOutputStream", "sendBroadcast", "startActivity", "startService");

    private static final class Origin {
        final String file;
        final long line;
        final String kind;
        Origin(String file, long line, String kind) {
            this.file = file; this.line = line; this.kind = kind;
        }
    }

    private static final class Method {
        final CompilationUnitTree unit;
        final TreePath path;
        final MethodTree tree;
        final String file;
        final String name;
        final String signature;
        final List<Element> params;
        Method(CompilationUnitTree unit, TreePath path, MethodTree tree,
               String file, ExecutableElement symbol, Trees trees) {
            this.unit = unit;
            this.path = path;
            this.tree = tree;
            this.file = file;
            this.name = symbol.getSimpleName().toString();
            Element owner = symbol.getEnclosingElement();
            String type = owner instanceof TypeElement
                ? ((TypeElement) owner).getQualifiedName().toString() : owner.toString();
            List<String> types = new ArrayList<>();
            for (VariableElement param : symbol.getParameters()) {
                types.add(param.asType().toString());
            }
            this.signature = type + "#" + name + "(" + String.join(",", types) + ")";
            this.params = new ArrayList<>();
            for (VariableTree parameter : tree.getParameters()) {
                params.add(trees.getElement(new TreePath(path, parameter)));
            }
        }
    }

    private static final class Hop {
        final Method caller;
        final Method callee;
        final long line;
        Hop(Method caller, Method callee, long line) {
            this.caller = caller; this.callee = callee; this.line = line;
        }
    }

    private static String enc(String text) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
            text.getBytes(StandardCharsets.UTF_8));
    }

    private static String methodName(MethodInvocationTree call) {
        ExpressionTree select = call.getMethodSelect();
        if (select instanceof MemberSelectTree) {
            return ((MemberSelectTree) select).getIdentifier().toString();
        }
        if (select instanceof IdentifierTree) {
            return ((IdentifierTree) select).getName().toString();
        }
        return "";
    }

    private static boolean isSource(ExpressionTree expr) {
        if (!(expr instanceof MethodInvocationTree)) {
            return false;
        }
        MethodInvocationTree call = (MethodInvocationTree) expr;
        String name = methodName(call);
        if (!(name.equals("getDataString") || name.equals("getStringExtra")
              || name.equals("getData") || name.equals("getParcelableExtra"))) {
            return false;
        }
        if (!(call.getMethodSelect() instanceof MemberSelectTree)) {
            return false;
        }
        ExpressionTree receiver = ((MemberSelectTree) call.getMethodSelect()).getExpression();
        if (!(receiver instanceof MethodInvocationTree)) {
            return false;
        }
        MethodInvocationTree parent = (MethodInvocationTree) receiver;
        return methodName(parent).equals("getIntent") && parent.getArguments().isEmpty();
    }

    private static final class Engine {
        final Trees trees;
        final Map<ExecutableElement, Method> methods;
        final Set<String> recorded = new HashSet<>();
        final List<String> results = new ArrayList<>();
        int unknownBranches = 0;
        int visits = 0;
        int attemptedCalls = 0;
        boolean truncated = false;

        Engine(Trees trees, Map<ExecutableElement, Method> methods) {
            this.trees = trees; this.methods = methods;
        }

        long line(Method method, Tree node) {
            long offset = trees.getSourcePositions().getStartPosition(method.unit, node);
            return offset >= 0 && method.unit.getLineMap() != null
                ? method.unit.getLineMap().getLineNumber(offset) : -1;
        }

        Origin expression(Method method, ExpressionTree expr, TreePath path,
                          Map<Element, Origin> taint) {
            if (expr == null) return null;
            if (isSource(expr)) {
                long at = line(method, expr);
                return at > 0 ? new Origin(method.file, at,
                    "ANDROID_INTENT_SOURCE_SYNTAX_CUE") : null;
            }
            if (expr instanceof IdentifierTree) {
                Element symbol = trees.getElement(path);
                return taint.get(symbol);
            }
            if (expr instanceof ParenthesizedTree) {
                ExpressionTree inner = ((ParenthesizedTree) expr).getExpression();
                return expression(method, inner, new TreePath(path, inner), taint);
            }
            if (expr instanceof TypeCastTree) {
                ExpressionTree inner = ((TypeCastTree) expr).getExpression();
                return expression(method, inner, new TreePath(path, inner), taint);
            }
            return null;
        }

        void write(Origin origin, Method method, MethodInvocationTree call,
                   String sink, List<Hop> hops) {
            if (hops.isEmpty() || results.size() >= MAX_FLOWS) {
                if (results.size() >= MAX_FLOWS) truncated = true;
                return;
            }
            long sinkLine = line(method, call);
            if (sinkLine < 1) return;
            List<String> fields = new ArrayList<>();
            Collections.addAll(fields,
                origin.file, Long.toString(origin.line), origin.kind,
                method.file, Long.toString(sinkLine), method.name,
                method.signature, sink, Integer.toString(hops.size()));
            for (Hop hop : hops) {
                Collections.addAll(fields, hop.caller.file, hop.caller.name,
                    hop.caller.signature, Long.toString(hop.line),
                    hop.callee.file, hop.callee.name,
                    Long.toString(line(hop.callee, hop.callee.tree)),
                    hop.callee.signature);
            }
            List<String> encoded = new ArrayList<>();
            for (String field : fields) encoded.add(enc(field));
            String record = "FLOW\t" + String.join("\t", encoded);
            if (recorded.add(record)) results.add(record);
        }

        void invoke(Method method, MethodInvocationTree call, TreePath path,
                    Map<Element, Origin> taint, List<Hop> hops,
                    Set<String> active, int depth) {
            String name = methodName(call);
            List<? extends ExpressionTree> args = call.getArguments();
            List<Origin> passed = new ArrayList<>();
            for (ExpressionTree arg : args) {
                passed.add(expression(method, arg, new TreePath(path, arg), taint));
            }
            boolean anything = false;
            for (Origin origin : passed) {
                if (origin != null) anything = true;
            }
            if (!anything) return;
            if (SINK_CUES.contains(name)) {
                for (Origin origin : passed) {
                    if (origin != null) {
                        write(origin, method, call, name, hops);
                        break;
                    }
                }
            }
            if (depth >= MAX_HOPS || attemptedCalls++ >= MAX_VISITS) {
                truncated = true;
                return;
            }
            Element target = trees.getElement(new TreePath(path, call.getMethodSelect()));
            if (!(target instanceof ExecutableElement)) return;
            Method callee = methods.get(target);
            if (callee == null || callee.file.equals(method.file)
                || callee.params.size() != passed.size()) return;
            String key = callee.signature + "@" + callee.file;
            if (active.contains(key)) return;
            Map<Element, Origin> inherited = new HashMap<>();
            for (int i = 0; i < passed.size(); i++) {
                if (passed.get(i) != null && callee.params.get(i) != null) {
                    inherited.put(callee.params.get(i), passed.get(i));
                }
            }
            if (inherited.isEmpty()) return;
            List<Hop> next = new ArrayList<>(hops);
            next.add(new Hop(method, callee, line(method, call)));
            process(callee, inherited, next, active, depth + 1);
        }

        void process(Method method, Map<Element, Origin> inherited,
                     List<Hop> hops, Set<String> active, int depth) {
            if (method.tree.getBody() == null || visits >= MAX_VISITS
                    || results.size() >= MAX_FLOWS) {
                if (visits >= MAX_VISITS || results.size() >= MAX_FLOWS) truncated = true;
                return;
            }
            String key = method.signature + "@" + method.file;
            if (active.contains(key)) return;
            active.add(key);
            Map<Element, Origin> taint = new HashMap<>(inherited);
            if (hops.isEmpty() && method.name.equals("onNewIntent")
                    && !method.params.isEmpty() && method.params.get(0) != null) {
                long at = line(method, method.tree.getParameters().get(0));
                if (at > 0) taint.put(method.params.get(0),
                    new Origin(method.file, at, "ONNEWINTENT_PARAMETER_NAME_CUE"));
            }
            BlockTree body = method.tree.getBody();
            TreePath bodyPath = new TreePath(method.path, body);
            for (StatementTree statement : body.getStatements()) {
                visits++;
                if (visits >= MAX_VISITS || results.size() >= MAX_FLOWS) {
                    truncated = true;
                    break;
                }
                TreePath statementPath = new TreePath(bodyPath, statement);
                if (statement instanceof VariableTree) {
                    VariableTree variable = (VariableTree) statement;
                    Element symbol = trees.getElement(statementPath);
                    ExpressionTree init = variable.getInitializer();
                    Origin value = init == null ? null : expression(
                        method, init, new TreePath(statementPath, init), taint);
                    if (symbol != null) {
                        if (value != null) taint.put(symbol, value);
                        else taint.remove(symbol);
                    }
                    if (init instanceof MethodInvocationTree) {
                        invoke(method, (MethodInvocationTree) init,
                               new TreePath(statementPath, init),
                               taint, hops, active, depth);
                    }
                } else if (statement instanceof ExpressionStatementTree) {
                    ExpressionTree expression = ((ExpressionStatementTree) statement).getExpression();
                    TreePath exprPath = new TreePath(statementPath, expression);
                    if (expression instanceof AssignmentTree) {
                        AssignmentTree assignment = (AssignmentTree) expression;
                        ExpressionTree variable = assignment.getVariable();
                        ExpressionTree rhs = assignment.getExpression();
                        Element symbol = trees.getElement(new TreePath(exprPath, variable));
                        Origin source = expression(method, rhs,
                            new TreePath(exprPath, rhs), taint);
                        if (symbol != null) {
                            if (source != null) taint.put(symbol, source);
                            else taint.remove(symbol);
                        }
                        if (rhs instanceof MethodInvocationTree) {
                            invoke(method, (MethodInvocationTree) rhs,
                                new TreePath(exprPath, rhs),
                                taint, hops, active, depth);
                        }
                    } else if (expression instanceof MethodInvocationTree) {
                        invoke(method, (MethodInvocationTree) expression,
                            exprPath, taint, hops, active, depth);
                    } else {
                        // e.g. increments/compound assignments may alter a tracked value.
                        taint.clear();
                        unknownBranches++;
                    }
                } else if (statement instanceof ReturnTree
                           || statement instanceof ThrowTree) {
                    break;
                } else if (statement instanceof EmptyStatementTree) {
                    continue;
                } else {
                    // Do not infer a feasible path through conditions, loops,
                    // try/catch, synchronized blocks or early-exit switches.
                    taint.clear();
                    unknownBranches++;
                }
            }
            active.remove(key);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3 || args.length > MAX_FILES + 2) {
            throw new IllegalArgumentException("root, empty classpath and bounded Java files required");
        }
        Path root = Paths.get(args[0]).toRealPath();
        Path emptyClasspath = Paths.get(args[1]).toRealPath();
        List<Path> sources = new ArrayList<>();
        Set<Path> known = new HashSet<>();
        for (int i = 2; i < args.length; i++) {
            Path path = Paths.get(args[i]).toRealPath();
            if (!path.startsWith(root) || path.equals(root)
                    || !path.toString().endsWith(".java") || !known.add(path)) {
                throw new IllegalArgumentException("unsafe or duplicate Java source");
            }
            sources.add(path);
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("JDK compiler unavailable");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(
                diagnostics, null, StandardCharsets.UTF_8)) {
            Iterable<? extends JavaFileObject> files = manager.getJavaFileObjectsFromPaths(sources);
            List<String> options = List.of("-proc:none", "-classpath", emptyClasspath.toString(),
                "-sourcepath", emptyClasspath.toString(), "-implicit:none",
                "-Xlint:none", "-encoding", "UTF-8");
            JavacTask task = (JavacTask) compiler.getTask(
                new StringWriter(), manager, diagnostics, options, null, files);
            List<CompilationUnitTree> units = new ArrayList<>();
            for (CompilationUnitTree unit : task.parse()) units.add(unit);
            task.analyze();
            Trees trees = Trees.instance(task);
            Map<ExecutableElement, Method> methods = new LinkedHashMap<>();
            for (CompilationUnitTree unit : units) {
                Path path = Paths.get(unit.getSourceFile().toUri()).toRealPath();
                String relative = root.relativize(path).toString().replace('\\', '/');
                new TreePathScanner<Void, Void>() {
                    @Override
                    public Void visitMethod(MethodTree tree, Void unused) {
                        Element symbol = trees.getElement(getCurrentPath());
                        if (symbol instanceof ExecutableElement) {
                            methods.put((ExecutableElement) symbol,
                                new Method(unit, getCurrentPath(), tree, relative,
                                    (ExecutableElement) symbol, trees));
                        }
                        return super.visitMethod(tree, unused);
                    }
                }.scan(unit, null);
            }
            Engine engine = new Engine(trees, methods);
            for (Method method : methods.values()) {
                if (engine.truncated) break;
                engine.process(method, Map.of(), new ArrayList<>(), new HashSet<>(), 0);
            }
            long errors = diagnostics.getDiagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR).count();
            System.out.println("META\t" + sources.size() + "\t" + errors
                + "\t" + methods.size() + "\t" + engine.results.size()
                + "\t" + engine.unknownBranches
                + "\t" + (engine.truncated ? "1" : "0"));
            Collections.sort(engine.results);
            for (String result : engine.results) System.out.println(result);
        }
    }
}
