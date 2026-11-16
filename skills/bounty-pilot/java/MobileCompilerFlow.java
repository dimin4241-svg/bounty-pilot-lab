/*
 * Conservative Java AST intraprocedural def-use and interfile parameter flow.
 * Operator-provided Java is parsed/analyzed by JDK 17 without running classes,
 * loading application classpath or invoking annotation processors.
 *
 * This is intentionally NOT a complete taint or control-flow analysis.
 * It handles ordered local assignments, fixed-dispatch Java method calls,
 * strictly pure local return summaries, private this.field slots, and narrow
 * assignment-only conditional joins. Unknown branches, aliases and side effects
 * invalidate state rather than create imaginary flows.
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
    // Return/field summaries include a call and a return for each accessor.
    private static final int MAX_HOPS = 6;
    private static final int MAX_CALL_DEPTH = 3;
    private static final int MAX_FLOWS = 120;
    private static final int MAX_VISITS = 12000;
    private static final Set<String> SINK_CUES = Set.of(
        "loadUrl", "loadDataWithBaseURL", "setResult", "openFileOutput",
        "openOutputStream", "sendBroadcast", "startActivity", "startService");

    private static final class Origin {
        final String file;
        final long line;
        final String kind;
        final List<Hop> route;
        final boolean capsuleDerived;
        Origin(String file, long line, String kind) {
            this(file, line, kind, List.of(), false);
        }
        Origin(String file, long line, String kind, List<Hop> route) {
            this(file, line, kind, route, false);
        }
        Origin(String file, long line, String kind, List<Hop> route,
               boolean capsuleDerived) {
            this.file = file; this.line = line; this.kind = kind;
            this.route = List.copyOf(route);
            this.capsuleDerived = capsuleDerived;
        }
        Origin through(Hop hop) {
            List<Hop> next = new ArrayList<>(route);
            next.add(hop);
            return new Origin(file, line, kind, next, capsuleDerived);
        }
        Origin fromCapsule() {
            return new Origin(file, line, kind, route, true);
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
        final String kind;
        Hop(Method caller, Method callee, long line) {
            this(caller, callee, line, "METHOD_CALL");
        }
        Hop(Method caller, Method callee, long line, String kind) {
            this.caller = caller; this.callee = callee;
            this.line = line; this.kind = kind;
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

    // A javac symbol names a declaration, not necessarily the implementation
    // executed by a virtual call. Traverse only fixed-dispatch call edges.
    private static boolean fixedDispatch(MethodInvocationTree call,
                                         ExecutableElement target) {
        Set<Modifier> modifiers = target.getModifiers();
        if (modifiers.contains(Modifier.STATIC) ||
            modifiers.contains(Modifier.PRIVATE) ||
            modifiers.contains(Modifier.FINAL)) return true;
        Element owner = target.getEnclosingElement();
        if (owner != null && owner.getModifiers().contains(Modifier.FINAL)) return true;
        if (call.getMethodSelect() instanceof MemberSelectTree) {
            ExpressionTree receiver =
                ((MemberSelectTree) call.getMethodSelect()).getExpression();
            if (receiver instanceof IdentifierTree &&
                ((IdentifierTree) receiver).getName().contentEquals("super")) return true;
        }
        return false;
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
            if (expr instanceof IdentifierTree || expr instanceof MemberSelectTree) {
                Element symbol = trees.getElement(path);
                if (localSymbol(symbol) || fieldOnThis(path, expr)) {
                    return taint.get(symbol);
                }
                return null;
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
            List<Hop> route = origin.route.isEmpty() ? hops : origin.route;
            if (route.isEmpty() || route.size() > MAX_HOPS
                    || results.size() >= MAX_FLOWS) {
                if (results.size() >= MAX_FLOWS) truncated = true;
                return;
            }
            long sinkLine = line(method, call);
            if (sinkLine < 1) return;
            List<String> fields = new ArrayList<>();
            Collections.addAll(fields,
                origin.file, Long.toString(origin.line), origin.kind,
                method.file, Long.toString(sinkLine), method.name,
                method.signature, sink, Integer.toString(route.size()));
            for (Hop hop : route) {
                Collections.addAll(fields, hop.caller.file, hop.caller.name,
                    hop.caller.signature, Long.toString(hop.line),
                    hop.callee.file, hop.callee.name,
                    Long.toString(line(hop.callee, hop.callee.tree)),
                    hop.callee.signature, hop.kind);
            }
            List<String> encoded = new ArrayList<>();
            for (String field : fields) encoded.add(enc(field));
            String record = "FLOW\t" + String.join("\t", encoded);
            if (recorded.add(record)) results.add(record);
        }

        // Private fields are tracked only on the current 'this' object.
        // No receiver aliases, static fields, arrays or field-to-field aliases.
        boolean fieldOnThis(TreePath path, ExpressionTree expr) {
            Element symbol = trees.getElement(path);
            if (symbol == null || symbol.getKind() != ElementKind.FIELD ||
                    !symbol.getModifiers().contains(Modifier.PRIVATE) ||
                    symbol.getModifiers().contains(Modifier.STATIC)) return false;
            if (expr instanceof IdentifierTree) return true;
            if (!(expr instanceof MemberSelectTree)) return false;
            ExpressionTree receiver = ((MemberSelectTree) expr).getExpression();
            return receiver instanceof IdentifierTree &&
                ((IdentifierTree) receiver).getName().contentEquals("this");
        }

        void clearFields(Map<Element, Origin> taint) {
            taint.keySet().removeIf(symbol -> symbol != null &&
                symbol.getKind() == ElementKind.FIELD);
        }

        boolean returnArgumentSimple(ExpressionTree expr) {
            if (simpleValue(expr) || isSource(expr)) return true;
            if (expr instanceof TypeCastTree) {
                return returnArgumentSimple(((TypeCastTree) expr).getExpression());
            }
            return false;
        }

        // Summarize ONLY an ordinary Java helper whose complete body consists
        // of direct local declarations/assignments and one final return.
        // Unknown calls, field reads/writes, branches and exceptions reject it.
        Origin resolveReturn(Method caller, MethodInvocationTree call, TreePath path,
                             Map<Element, Origin> callerState, Set<String> active,
                             int depth) {
            if (depth >= MAX_CALL_DEPTH || attemptedCalls++ >= MAX_VISITS) {
                truncated = true;
                return null;
            }
            Element target = trees.getElement(new TreePath(path, call.getMethodSelect()));
            if (!(target instanceof ExecutableElement) ||
                    !fixedDispatch(call, (ExecutableElement) target)) return null;
            Method callee = methods.get(target);
            if (callee == null || callee.tree.getBody() == null ||
                    callee.params.size() != call.getArguments().size()) return null;
            String key = callee.signature + "@" + callee.file;
            if (active.contains(key)) return null;
            List<Origin> values = new ArrayList<>();
            boolean anything = false;
            for (ExpressionTree arg : call.getArguments()) {
                if (!returnArgumentSimple(arg)) return null;
                Origin origin = expression(caller, arg, new TreePath(path, arg), callerState);
                values.add(origin);
                if (origin != null) anything = true;
            }
            if (!anything) return null;

            Hop hop = new Hop(caller, callee, line(caller, call));
            Map<Element, Origin> locals = new HashMap<>();
            for (int i = 0; i < values.size(); i++) {
                Origin origin = values.get(i);
                if (origin != null) {
                    // A return edge must bring execution back into caller.
                    if (origin.route.size() + 2 > MAX_HOPS) return null;
                    locals.put(callee.params.get(i), origin.through(hop));
                }
            }
            Set<String> nextActive = new HashSet<>(active);
            nextActive.add(key);
            BlockTree body = callee.tree.getBody();
            TreePath bodyPath = new TreePath(callee.path, body);
            List<? extends StatementTree> statements = body.getStatements();
            for (int i = 0; i < statements.size(); i++) {
                StatementTree statement = statements.get(i);
                if (++visits >= MAX_VISITS) {
                    truncated = true;
                    return null;
                }
                TreePath statementPath = new TreePath(bodyPath, statement);
                if (statement instanceof EmptyStatementTree) continue;
                if (statement instanceof ReturnTree && i == statements.size() - 1) {
                    ExpressionTree result = ((ReturnTree) statement).getExpression();
                    if (result == null || !returnArgumentSimple(result)) return null;
                    Origin returned = expression(callee, result,
                        new TreePath(statementPath, result), locals);
                    return returned == null ? null : returned.through(
                        new Hop(callee, caller, line(callee, statement),
                                "RETURN_TO_CALLER"));
                }
                if (statement instanceof VariableTree) {
                    VariableTree declaration = (VariableTree) statement;
                    Element symbol = trees.getElement(statementPath);
                    if (!localSymbol(symbol)) return null;
                    ExpressionTree init = declaration.getInitializer();
                    if (init != null && !simpleValue(init)) return null;
                    Origin value = init == null ? null : expression(callee, init,
                        new TreePath(statementPath, init), locals);
                    if (value == null) locals.remove(symbol);
                    else locals.put(symbol, value);
                    continue;
                }
                if (statement instanceof ExpressionStatementTree) {
                    ExpressionTree expr = ((ExpressionStatementTree) statement).getExpression();
                    if (!(expr instanceof AssignmentTree)) return null;
                    TreePath expressionPath = new TreePath(statementPath, expr);
                    AssignmentTree assignment = (AssignmentTree) expr;
                    ExpressionTree variable = assignment.getVariable();
                    ExpressionTree rhs = assignment.getExpression();
                    if (!(variable instanceof IdentifierTree) || !simpleValue(rhs)) return null;
                    Element symbol = trees.getElement(new TreePath(expressionPath, variable));
                    if (!localSymbol(symbol)) return null;
                    Origin value = expression(callee, rhs,
                        new TreePath(expressionPath, rhs), locals);
                    if (value == null) locals.remove(symbol);
                    else locals.put(symbol, value);
                    continue;
                }
                return null;
            }
            return null;
        }

        // A value produced by a known, pure return helper can be used in a
        // local assignment or directly as a call argument. No other nested
        // calls are assumed to preserve taint.
        Origin value(Method method, ExpressionTree expr, TreePath path,
                     Map<Element, Origin> taint, Set<String> active, int depth) {
            if (expr == null) return null;
            Origin direct = expression(method, expr, path, taint);
            if (direct != null) return direct;
            if (expr instanceof MethodInvocationTree) {
                return resolveReturn(method, (MethodInvocationTree) expr, path,
                    taint, active, depth);
            }
            if (expr instanceof ParenthesizedTree) {
                ExpressionTree inner = ((ParenthesizedTree) expr).getExpression();
                return value(method, inner, new TreePath(path, inner),
                    taint, active, depth);
            }
            if (expr instanceof TypeCastTree) {
                ExpressionTree inner = ((TypeCastTree) expr).getExpression();
                return value(method, inner, new TreePath(path, inner),
                    taint, active, depth);
            }
            return null;
        }

        void invoke(Method method, MethodInvocationTree call, TreePath path,
                    Map<Element, Origin> taint, List<Hop> hops,
                    Set<String> active, int depth) {
            try {
                String name = methodName(call);
                List<? extends ExpressionTree> args = call.getArguments();
                List<Origin> passed = new ArrayList<>();
                for (ExpressionTree arg : args) {
                    passed.add(value(method, arg, new TreePath(path, arg),
                        taint, active, depth));
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
                if (depth >= MAX_CALL_DEPTH || attemptedCalls++ >= MAX_VISITS) {
                    truncated = true;
                    return;
                }
                Element target = trees.getElement(new TreePath(path, call.getMethodSelect()));
                if (!(target instanceof ExecutableElement)) return;
                Method callee = methods.get(target);
                if (callee == null || callee.params.size() != passed.size()
                    || !fixedDispatch(call, (ExecutableElement) target)) return;
                String key = callee.signature + "@" + callee.file;
                if (active.contains(key)) return;
                Map<Element, Origin> inherited = new HashMap<>();
                List<Hop> next = new ArrayList<>(hops);
                Hop hop = new Hop(method, callee, line(method, call));
                next.add(hop);
                for (int i = 0; i < passed.size(); i++) {
                    Origin origin = passed.get(i);
                    if (origin != null && callee.params.get(i) != null
                            && origin.route.size() < MAX_HOPS) {
                        inherited.put(callee.params.get(i), origin.through(hop));
                    }
                }
                if (inherited.isEmpty()) return;
                process(callee, inherited, next, active, depth + 1);
            } finally {
                // An unmodeled invoked method may mutate this.privateField.
                // Drop field provenance after evaluating call arguments.
                clearFields(taint);
            }
        }


        // Conditions are inspected only for simple, non-mutating expression
        // shapes. We intentionally never inspect sinks inside branch bodies.
        boolean simpleCondition(ExpressionTree expr) {
            if (expr instanceof IdentifierTree || expr instanceof LiteralTree) return true;
            if (expr instanceof ParenthesizedTree) {
                return simpleCondition(((ParenthesizedTree) expr).getExpression());
            }
            if (expr instanceof UnaryTree && expr.getKind() == Tree.Kind.LOGICAL_COMPLEMENT) {
                return simpleCondition(((UnaryTree) expr).getExpression());
            }
            if (expr instanceof BinaryTree) {
                Tree.Kind kind = expr.getKind();
                if (kind != Tree.Kind.CONDITIONAL_AND && kind != Tree.Kind.CONDITIONAL_OR
                    && kind != Tree.Kind.EQUAL_TO && kind != Tree.Kind.NOT_EQUAL_TO
                    && kind != Tree.Kind.LESS_THAN && kind != Tree.Kind.LESS_THAN_EQUAL
                    && kind != Tree.Kind.GREATER_THAN && kind != Tree.Kind.GREATER_THAN_EQUAL) {
                    return false;
                }
                BinaryTree binary = (BinaryTree) expr;
                return simpleCondition(binary.getLeftOperand())
                    && simpleCondition(binary.getRightOperand());
            }
            return false;
        }

        boolean simpleValue(ExpressionTree expr) {
            if (expr == null || expr instanceof LiteralTree ||
                expr instanceof IdentifierTree) return true;
            if (expr instanceof ParenthesizedTree) {
                return simpleValue(((ParenthesizedTree) expr).getExpression());
            }
            return false;
        }

        boolean localSymbol(Element symbol) {
            return symbol != null && (symbol.getKind() == ElementKind.LOCAL_VARIABLE
                || symbol.getKind() == ElementKind.PARAMETER);
        }

        boolean branchAssignments(Method method, StatementTree statement,
                                  TreePath path, Map<Element, Origin> state) {
            if (statement instanceof EmptyStatementTree) return true;
            if (statement instanceof BlockTree) {
                for (StatementTree nested : ((BlockTree) statement).getStatements()) {
                    if (!branchAssignments(method, nested,
                            new TreePath(path, nested), state)) return false;
                }
                return true;
            }
            Element symbol;
            ExpressionTree rhs;
            TreePath rhsPath = null;
            if (statement instanceof VariableTree) {
                symbol = trees.getElement(path);
                rhs = ((VariableTree) statement).getInitializer();
                if (rhs != null) rhsPath = new TreePath(path, rhs);
            } else if (statement instanceof ExpressionStatementTree) {
                ExpressionTree expr = ((ExpressionStatementTree) statement).getExpression();
                if (!(expr instanceof AssignmentTree)) return false;
                TreePath assignmentPath = new TreePath(path, expr);
                AssignmentTree assignment = (AssignmentTree) expr;
                if (!(assignment.getVariable() instanceof IdentifierTree)) return false;
                symbol = trees.getElement(new TreePath(assignmentPath,
                    assignment.getVariable()));
                rhs = assignment.getExpression();
                rhsPath = new TreePath(assignmentPath, rhs);
            } else {
                return false;
            }
            if (!localSymbol(symbol) || !simpleValue(rhs)) return false;
            Origin value = rhs == null ? null : expression(method, rhs, rhsPath, state);
            if (value == null) state.remove(symbol);
            else state.put(symbol, value);
            return true;
        }

        // A join must preserve the same *provenance route*, not only the
        // same source anchor. Two wrappers from the same input are not
        // interchangeable evidence of one confirmed method chain.
        boolean sameOrigin(Origin a, Origin b) {
            if (a == null || b == null || !a.file.equals(b.file)
                    || a.line != b.line || !a.kind.equals(b.kind)
                    || a.capsuleDerived != b.capsuleDerived
                    || a.route.size() != b.route.size()) return false;
            for (int i = 0; i < a.route.size(); i++) {
                Hop x = a.route.get(i), y = b.route.get(i);
                if (!x.kind.equals(y.kind) || x.line != y.line
                        || !x.caller.file.equals(y.caller.file)
                        || !x.caller.signature.equals(y.caller.signature)
                        || !x.callee.file.equals(y.callee.file)
                        || !x.callee.signature.equals(y.callee.signature)) {
                    return false;
                }
            }
            return true;
        }

        boolean joinConditional(Method method, IfTree tree, TreePath path,
                                Map<Element, Origin> state) {
            if (!simpleCondition(tree.getCondition())) return false;
            Map<Element, Origin> onTrue = new HashMap<>(state);
            Map<Element, Origin> onFalse = new HashMap<>(state);
            StatementTree thenStatement = tree.getThenStatement();
            StatementTree elseStatement = tree.getElseStatement();
            if (!branchAssignments(method, thenStatement,
                    new TreePath(path, thenStatement), onTrue)) return false;
            if (elseStatement != null && !branchAssignments(method, elseStatement,
                    new TreePath(path, elseStatement), onFalse)) return false;
            state.clear();
            for (Map.Entry<Element, Origin> entry : onTrue.entrySet()) {
                Origin a = entry.getValue();
                Origin b = onFalse.get(entry.getKey());
                if (sameOrigin(a, b)) state.put(entry.getKey(), a);
            }
            return true;
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
                    Origin value = init == null ? null : value(
                        method, init, new TreePath(statementPath, init), taint, active, depth);
                    if (localSymbol(symbol)) {
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
                        Origin source = value(method, rhs,
                            new TreePath(exprPath, rhs), taint, active, depth);
                        if (symbol != null && (localSymbol(symbol) ||
                                fieldOnThis(new TreePath(exprPath, variable), variable))) {
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
                } else if (statement instanceof IfTree) {
                    unknownBranches++;
                    if (!joinConditional(method, (IfTree) statement,
                            statementPath, taint)) taint.clear();
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


    // This is deliberately not a general Java heap analysis. A Capsule is
    // freshly allocated by the current method, cannot escape, and is tracked
    // only while all aliases and operations remain explicitly understood.
    private static final class Capsule {
        final TypeElement type;
        final Map<Element, Origin> fields = new HashMap<>();
        boolean escaped;
        Capsule(TypeElement type) { this.type = type; }
        void escape() { escaped = true; fields.clear(); }
    }

    private static final class CapsuleEngine {
        final Engine engine;
        final Trees trees;
        final Map<ExecutableElement, Method> methods;
        final Map<TypeElement, Boolean> safeTypes = new HashMap<>();
        private static final int MAX_CAPSULES_PER_METHOD = 24;

        CapsuleEngine(Engine engine) {
            this.engine = engine;
            this.trees = engine.trees;
            this.methods = engine.methods;
        }

        boolean safeType(TypeElement type) {
            Boolean cached = safeTypes.get(type);
            if (cached != null) return cached;
            boolean valid = false;
            // Require an isolated, final, no-arg type whose allocation cannot
            // run a user-defined constructor or escaping initializer.
            if (type.getModifiers().contains(Modifier.FINAL)
                    && (type.getNestingKind() == NestingKind.TOP_LEVEL
                        || (type.getNestingKind() == NestingKind.MEMBER
                            && type.getModifiers().contains(Modifier.STATIC)))) {
                Tree tree = trees.getTree(type);
                if (tree instanceof ClassTree) {
                    ClassTree clazz = (ClassTree) tree;
                    valid = clazz.getExtendsClause() == null;
                    for (Tree member : clazz.getMembers()) {
                        if (!valid) break;
                        if (member instanceof BlockTree) {
                            if (!((BlockTree) member).isStatic()) valid = false;
                        } else if (member instanceof VariableTree) {
                            VariableTree field = (VariableTree) member;
                            Element symbol = trees.getElement(new TreePath(
                                trees.getPath(type), field));
                            if (symbol != null &&
                                    !symbol.getModifiers().contains(Modifier.STATIC) &&
                                    field.getInitializer() != null &&
                                    !(field.getInitializer() instanceof LiteralTree)) {
                                valid = false;
                            }
                        } else if (member instanceof MethodTree) {
                            MethodTree method = (MethodTree) member;
                            if (method.getReturnType() == null) {
                                // Javac injects a default constructor during
                                // analyze() without an actual source span.
                                // Explicit constructors have source end offsets.
                                CompilationUnitTree unit =
                                    trees.getPath(type).getCompilationUnit();
                                long ctorEnd = trees.getSourcePositions()
                                    .getEndPosition(unit, member);
                                // The injected default constructor has no
                                // source end position. A constructor written
                                // by the developer has a source span even if
                                // its body is empty.
                                if (ctorEnd >= 0) valid = false;
                            }
                        }
                    }
                }
            }
            safeTypes.put(type, valid);
            return valid;
        }

        Capsule allocated(ExpressionTree expr, TreePath path) {
            if (!(expr instanceof NewClassTree)) return null;
            NewClassTree constructor = (NewClassTree) expr;
            if (constructor.getClassBody() != null ||
                    !constructor.getArguments().isEmpty() ||
                    constructor.getEnclosingExpression() != null) return null;
            Element ctor = trees.getElement(path);
            if (ctor == null || ctor.getKind() != ElementKind.CONSTRUCTOR ||
                    !(ctor.getEnclosingElement() instanceof TypeElement)) return null;
            TypeElement type = (TypeElement) ctor.getEnclosingElement();
            return safeType(type) ? new Capsule(type) : null;
        }

        // No casts, array receivers, dynamic field lookups or arbitrary
        // 'this' aliases: only identifiers compiler-resolved to local refs.
        Capsule receiver(MethodInvocationTree call, TreePath path,
                         Map<Element, Capsule> refs) {
            if (!(call.getMethodSelect() instanceof MemberSelectTree)) return null;
            MemberSelectTree select = (MemberSelectTree) call.getMethodSelect();
            ExpressionTree recv = select.getExpression();
            if (!(recv instanceof IdentifierTree)) return null;
            Element symbol = trees.getElement(new TreePath(
                new TreePath(path, select), recv));
            Capsule capsule = refs.get(symbol);
            return capsule != null && !capsule.escaped ? capsule : null;
        }

        Method bound(MethodInvocationTree call, TreePath path,
                     Capsule capsule) {
            Element target = trees.getElement(new TreePath(
                path, call.getMethodSelect()));
            if (!(target instanceof ExecutableElement) ||
                    !fixedDispatch(call, (ExecutableElement) target)) return null;
            Method method = methods.get(target);
            if (method == null || method.tree.getBody() == null) return null;
            Element owner = target.getEnclosingElement();
            return owner.equals(capsule.type) ? method : null;
        }

        Element directPrivateField(Method method, ExpressionTree expr,
                                   TreePath path, Capsule capsule) {
            if (!engine.fieldOnThis(path, expr)) return null;
            Element field = trees.getElement(path);
            if (field == null || !field.getEnclosingElement().equals(capsule.type)
                    || !field.asType().toString().equals("java.lang.String")) return null;
            return field;
        }

        static final class Access {
            final Capsule capsule;
            final Method method;
            final Element field;
            final long anchor;
            Access(Capsule capsule, Method method, Element field, long anchor) {
                this.capsule = capsule; this.method = method;
                this.field = field; this.anchor = anchor;
            }
        }

        Access setter(MethodInvocationTree call, TreePath path,
                      Map<Element, Capsule> refs) {
            Capsule capsule = receiver(call, path, refs);
            if (capsule == null || call.getArguments().size() != 1) return null;
            Method method = bound(call, path, capsule);
            if (method == null || method.params.size() != 1 ||
                    method.tree.getBody().getStatements().size() != 1) return null;
            StatementTree stmt = method.tree.getBody().getStatements().get(0);
            if (!(stmt instanceof ExpressionStatementTree)) return null;
            ExpressionTree expr = ((ExpressionStatementTree) stmt).getExpression();
            if (!(expr instanceof AssignmentTree)) return null;
            TreePath bodyPath = new TreePath(method.path, method.tree.getBody());
            TreePath stmtPath = new TreePath(bodyPath, stmt);
            TreePath exprPath = new TreePath(stmtPath, expr);
            AssignmentTree assignment = (AssignmentTree) expr;
            Element field = directPrivateField(method, assignment.getVariable(),
                new TreePath(exprPath, assignment.getVariable()), capsule);
            ExpressionTree rhs = assignment.getExpression();
            Element source = trees.getElement(new TreePath(exprPath, rhs));
            if (field == null || !(rhs instanceof IdentifierTree) ||
                    !method.params.get(0).equals(source)) return null;
            return new Access(capsule, method, field, engine.line(method, stmt));
        }

        Access getter(MethodInvocationTree call, TreePath path,
                      Map<Element, Capsule> refs) {
            Capsule capsule = receiver(call, path, refs);
            if (capsule == null || !call.getArguments().isEmpty()) return null;
            Method method = bound(call, path, capsule);
            if (method == null || !method.params.isEmpty() ||
                    method.tree.getBody().getStatements().size() != 1) return null;
            StatementTree stmt = method.tree.getBody().getStatements().get(0);
            if (!(stmt instanceof ReturnTree)) return null;
            ExpressionTree expr = ((ReturnTree) stmt).getExpression();
            if (expr == null) return null;
            TreePath bodyPath = new TreePath(method.path, method.tree.getBody());
            TreePath stmtPath = new TreePath(bodyPath, stmt);
            Element field = directPrivateField(method, expr,
                new TreePath(stmtPath, expr), capsule);
            return field == null ? null :
                new Access(capsule, method, field, engine.line(method, stmt));
        }

        Origin read(Method caller, MethodInvocationTree call, TreePath path,
                    Map<Element, Capsule> refs) {
            Access access = getter(call, path, refs);
            if (access == null) return null;
            Origin stored = access.capsule.fields.get(access.field);
            if (stored == null || stored.route.size() + 2 > MAX_HOPS) return null;
            Hop callEdge = new Hop(caller, access.method,
                engine.line(caller, call));
            Hop returnEdge = new Hop(access.method, caller,
                access.anchor, "RETURN_TO_CALLER");
            return stored.through(callEdge).through(returnEdge).fromCapsule();
        }

        Origin value(Method method, ExpressionTree expr, TreePath path,
                     Map<Element, Origin> locals,
                     Map<Element, Capsule> refs) {
            if (expr == null) return null;
            if (expr instanceof MethodInvocationTree) {
                MethodInvocationTree call = (MethodInvocationTree) expr;
                if (getter(call, path, refs) != null)
                    return read(method, call, path, refs);
            }
            if (expr instanceof ParenthesizedTree) {
                ExpressionTree inner = ((ParenthesizedTree) expr).getExpression();
                return value(method, inner, new TreePath(path, inner), locals, refs);
            }
            if (expr instanceof TypeCastTree) {
                ExpressionTree inner = ((TypeCastTree) expr).getExpression();
                return value(method, inner, new TreePath(path, inner), locals, refs);
            }
            // Leverage the prior precise local/pure-return summaries.
            return engine.value(method, expr, path, locals, new HashSet<>(), 0);
        }

        // A getter returning a String is not an object escape. Every other
        // expression mentioning a tracked object is conservatively treated
        // as a possible escape; no implicit alias recovery through casts.
        void escapeReferenced(TreePath path, Map<Element, Capsule> refs) {
            if (path == null || refs.isEmpty()) return;
            new TreePathScanner<Void, Void>() {
                @Override
                public Void visitIdentifier(IdentifierTree id, Void unused) {
                    Capsule capsule = refs.get(trees.getElement(getCurrentPath()));
                    if (capsule != null) capsule.escape();
                    return super.visitIdentifier(id, unused);
                }
            }.scan(path, null);
        }

        boolean isAllowedGetterArg(ExpressionTree expr, TreePath path,
                                   Map<Element, Capsule> refs) {
            if (expr instanceof MethodInvocationTree) {
                return getter((MethodInvocationTree) expr, path, refs) != null;
            }
            if (expr instanceof ParenthesizedTree) {
                ExpressionTree child = ((ParenthesizedTree) expr).getExpression();
                return isAllowedGetterArg(child, new TreePath(path, child), refs);
            }
            return false;
        }

        void applySetter(Method caller, MethodInvocationTree call, TreePath path,
                         Access access, Map<Element, Origin> locals,
                         Map<Element, Capsule> refs) {
            ExpressionTree arg = call.getArguments().get(0);
            TreePath argPath = new TreePath(path, arg);
            // This capsule model only stores strings, not other capsules.
            escapeReferenced(argPath, refs);
            if (access.capsule.escaped) return;
            Origin source = value(caller, arg, argPath, locals, refs);
            if (source == null || source.route.size() + 2 > MAX_HOPS) {
                access.capsule.fields.remove(access.field);
                return;
            }
            Hop callEdge = new Hop(caller, access.method,
                engine.line(caller, call));
            Hop returnEdge = new Hop(access.method, caller,
                access.anchor, "RETURN_TO_CALLER");
            access.capsule.fields.put(access.field,
                source.through(callEdge).through(returnEdge));
        }

        void flowCall(Method caller, MethodInvocationTree call, TreePath path,
                      Map<Element, Origin> locals,
                      Map<Element, Capsule> refs) {
            Access setter = setter(call, path, refs);
            if (setter != null) {
                applySetter(caller, call, path, setter, locals, refs);
                return;
            }
            if (getter(call, path, refs) != null) return; // read-only
            List<Origin> inputs = new ArrayList<>();
            boolean heapInput = false;
            for (ExpressionTree arg : call.getArguments()) {
                TreePath argPath = new TreePath(path, arg);
                Origin origin = value(caller, arg, argPath, locals, refs);
                inputs.add(origin);
                if (origin != null && origin.capsuleDerived) heapInput = true;
                if (!isAllowedGetterArg(arg, argPath, refs))
                    escapeReferenced(argPath, refs);
            }
            if (call.getMethodSelect() instanceof MemberSelectTree) {
                MemberSelectTree select = (MemberSelectTree) call.getMethodSelect();
                escapeReferenced(new TreePath(new TreePath(path, select),
                    select.getExpression()), refs);
            }
            if (!heapInput) return;
            if (SINK_CUES.contains(methodName(call))) {
                for (Origin origin : inputs) {
                    if (origin != null && origin.capsuleDerived) {
                        engine.write(origin, caller, call, methodName(call), List.of());
                        break;
                    }
                }
            }
            Element target = trees.getElement(new TreePath(path, call.getMethodSelect()));
            if (!(target instanceof ExecutableElement)
                    || !fixedDispatch(call, (ExecutableElement) target)) return;
            Method callee = methods.get(target);
            if (callee == null || callee.params.size() != inputs.size()
                    || callee.tree.getBody() == null) return;
            Hop hop = new Hop(caller, callee, engine.line(caller, call));
            Map<Element, Origin> inherited = new HashMap<>();
            for (int i = 0; i < inputs.size(); i++) {
                Origin origin = inputs.get(i);
                if (origin != null && origin.capsuleDerived &&
                        origin.route.size() + 1 <= MAX_HOPS) {
                    inherited.put(callee.params.get(i), origin.through(hop));
                }
            }
            if (inherited.isEmpty()) return;
            engine.process(callee, inherited, List.of(hop), new HashSet<>(), 1);
        }

        void process(Method method) {
            if (method.tree.getBody() == null || engine.truncated) return;
            Map<Element, Origin> locals = new HashMap<>();
            Map<Element, Capsule> refs = new HashMap<>();
            int allocations = 0;
            if (method.name.equals("onNewIntent") &&
                    !method.params.isEmpty() && method.params.get(0) != null) {
                long at = engine.line(method, method.tree.getParameters().get(0));
                if (at > 0) locals.put(method.params.get(0), new Origin(
                    method.file, at, "ONNEWINTENT_PARAMETER_NAME_CUE"));
            }
            BlockTree body = method.tree.getBody();
            TreePath bodyPath = new TreePath(method.path, body);
            for (StatementTree stmt : body.getStatements()) {
                if (++engine.visits >= MAX_VISITS || engine.results.size() >= MAX_FLOWS) {
                    engine.truncated = true; return;
                }
                TreePath stmtPath = new TreePath(bodyPath, stmt);
                if (stmt instanceof EmptyStatementTree) continue;
                if (stmt instanceof ReturnTree || stmt instanceof ThrowTree) return;
                if (stmt instanceof VariableTree) {
                    VariableTree variable = (VariableTree) stmt;
                    Element symbol = trees.getElement(stmtPath);
                    ExpressionTree init = variable.getInitializer();
                    TreePath initPath = init == null ? null : new TreePath(stmtPath, init);
                    Origin origin = value(method, init, initPath, locals, refs);
                    Capsule alias = null;
                    if (init instanceof IdentifierTree)
                        alias = refs.get(trees.getElement(initPath));
                    else if (init instanceof NewClassTree &&
                            allocations < MAX_CAPSULES_PER_METHOD) {
                        alias = allocated(init, initPath);
                        if (alias != null) allocations++;
                    } else if (initPath != null && !isAllowedGetterArg(init, initPath, refs))
                        escapeReferenced(initPath, refs);
                    if (engine.localSymbol(symbol)) {
                        if (origin == null) locals.remove(symbol);
                        else locals.put(symbol, origin);
                        if (alias == null) refs.remove(symbol);
                        else refs.put(symbol, alias);
                    }
                    continue;
                }
                if (stmt instanceof ExpressionStatementTree) {
                    ExpressionTree expr = ((ExpressionStatementTree) stmt).getExpression();
                    TreePath exprPath = new TreePath(stmtPath, expr);
                    if (expr instanceof MethodInvocationTree) {
                        flowCall(method, (MethodInvocationTree) expr, exprPath,
                            locals, refs);
                        continue;
                    }
                    if (expr instanceof AssignmentTree) {
                        AssignmentTree assignment = (AssignmentTree) expr;
                        ExpressionTree lhs = assignment.getVariable();
                        ExpressionTree rhs = assignment.getExpression();
                        TreePath lhsPath = new TreePath(exprPath, lhs);
                        TreePath rhsPath = new TreePath(exprPath, rhs);
                        Element symbol = trees.getElement(lhsPath);
                        Origin origin = value(method, rhs, rhsPath, locals, refs);
                        Capsule alias = null;
                        if (rhs instanceof IdentifierTree)
                            alias = refs.get(trees.getElement(rhsPath));
                        else if (rhs instanceof NewClassTree &&
                                allocations < MAX_CAPSULES_PER_METHOD) {
                            alias = allocated(rhs, rhsPath);
                            if (alias != null) allocations++;
                        } else if (!isAllowedGetterArg(rhs, rhsPath, refs))
                            escapeReferenced(rhsPath, refs);
                        if (engine.localSymbol(symbol) && lhs instanceof IdentifierTree) {
                            if (origin == null) locals.remove(symbol);
                            else locals.put(symbol, origin);
                            if (alias == null) refs.remove(symbol);
                            else refs.put(symbol, alias);
                        } else {
                            escapeReferenced(lhsPath, refs);
                            escapeReferenced(rhsPath, refs);
                        }
                        continue;
                    }
                }
                // No paths through unknown statements or mutations are inferred.
                locals.clear();
                refs.clear();
                engine.unknownBranches++;
            }
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
            CapsuleEngine capsules = new CapsuleEngine(engine);
            for (Method method : methods.values()) {
                if (engine.truncated) break;
                engine.process(method, Map.of(), new ArrayList<>(), new HashSet<>(), 0);
                if (!engine.truncated) capsules.process(method);
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
