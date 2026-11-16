/*
 * JDK 17 compiler AST-backed call graph for operator-supplied Java source.
 * Does not execute supplied source, run annotation processors, or emit classes.
 * Error diagnostics and partial-resolution limits are exported to the wrapper.
 */
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

public final class MobileCompilerGraph {
    private static final int MAX_EDGES = 3000;

    private static final class MethodInfo {
        final String file;
        final String name;
        final long line;
        final String signature;

        MethodInfo(String file, String name, long line, String signature) {
            this.file = file;
            this.name = name;
            this.line = line;
            this.signature = signature;
        }
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String declaration(ExecutableElement method) {
        Element owner = method.getEnclosingElement();
        String className = owner instanceof TypeElement
            ? ((TypeElement) owner).getQualifiedName().toString() : owner.toString();
        List<String> params = new ArrayList<>();
        method.getParameters().forEach(param -> params.add(param.asType().toString()));
        return className + "#" + method.getSimpleName() + "("
            + String.join(",", params) + ")";
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            throw new IllegalArgumentException("root, isolated classpath, Java sources required");
        }
        Path root = Paths.get(args[0]).toRealPath();
        Path emptyClasspath = Paths.get(args[1]).toRealPath();
        List<Path> sources = new ArrayList<>();
        Set<Path> known = new HashSet<>();
        for (int i = 2; i < args.length; i++) {
            Path candidate = Paths.get(args[i]).toRealPath();
            if (!candidate.startsWith(root) || candidate.equals(root)
                    || !candidate.toString().endsWith(".java")
                    || !known.add(candidate)) {
                throw new IllegalArgumentException("invalid or repeated source path");
            }
            sources.add(candidate);
        }
        if (sources.size() > 350) {
            throw new IllegalArgumentException("source count cap exceeded");
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("JDK with javac is required");
        }
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(
                diagnostics, null, StandardCharsets.UTF_8)) {
            Iterable<? extends JavaFileObject> files =
                manager.getJavaFileObjectsFromPaths(sources);
            List<String> options = List.of(
                "-proc:none", "-classpath", emptyClasspath.toString(),
                "-sourcepath", emptyClasspath.toString(),
                "-implicit:none", "-Xlint:none", "-encoding", "UTF-8");
            JavacTask task = (JavacTask) compiler.getTask(
                new StringWriter(), manager, diagnostics, options, null, files);
            List<CompilationUnitTree> units = new ArrayList<>();
            for (CompilationUnitTree unit : task.parse()) {
                units.add(unit);
            }
            task.analyze();
            Trees trees = Trees.instance(task);
            Map<ExecutableElement, MethodInfo> declarations = new HashMap<>();
            Set<String> acceptedFiles = new HashSet<>();
            for (Path file : sources) {
                acceptedFiles.add(root.relativize(file).toString().replace('\\', '/'));
            }

            for (CompilationUnitTree unit : units) {
                Path sourceFile = Paths.get(unit.getSourceFile().toUri()).toRealPath();
                String relative = root.relativize(sourceFile).toString().replace('\\', '/');
                if (!acceptedFiles.contains(relative)) {
                    continue;
                }
                new TreePathScanner<Void, Void>() {
                    @Override
                    public Void visitMethod(MethodTree node, Void unused) {
                        Element symbol = trees.getElement(getCurrentPath());
                        if (symbol instanceof ExecutableElement) {
                            ExecutableElement method = (ExecutableElement) symbol;
                            long pos = trees.getSourcePositions().getStartPosition(unit, node);
                            if (pos >= 0 && unit.getLineMap() != null) {
                                declarations.put(method, new MethodInfo(
                                    relative, method.getSimpleName().toString(),
                                    unit.getLineMap().getLineNumber(pos),
                                    declaration(method)));
                            }
                        }
                        return super.visitMethod(node, unused);
                    }
                }.scan(unit, null);
            }

            Set<String> edges = new HashSet<>();
            final boolean[] truncated = {false};
            for (CompilationUnitTree unit : units) {
                Path sourceFile = Paths.get(unit.getSourceFile().toUri()).toRealPath();
                String relative = root.relativize(sourceFile).toString().replace('\\', '/');
                if (!acceptedFiles.contains(relative)) {
                    continue;
                }
                new TreePathScanner<Void, Void>() {
                    private MethodInfo current;

                    @Override
                    public Void visitMethod(MethodTree node, Void unused) {
                        MethodInfo prior = current;
                        Element symbol = trees.getElement(getCurrentPath());
                        current = symbol instanceof ExecutableElement
                            ? declarations.get(symbol) : null;
                        try {
                            return super.visitMethod(node, unused);
                        } finally {
                            current = prior;
                        }
                    }

                    @Override
                    public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                        if (current != null) {
                            Element target = trees.getElement(
                                new TreePath(getCurrentPath(), node.getMethodSelect()));
                            MethodInfo callee = target instanceof ExecutableElement
                                ? declarations.get(target) : null;
                            if (callee != null && !callee.file.equals(current.file)) {
                                long pos = trees.getSourcePositions().getStartPosition(unit, node);
                                if (pos >= 0 && unit.getLineMap() != null) {
                                    long callLine = unit.getLineMap().getLineNumber(pos);
                                    String[] data = {
                                        current.file, current.name,
                                        Long.toString(current.line),
                                        callee.file, callee.name,
                                        Long.toString(callee.line),
                                        Long.toString(callLine),
                                        current.signature, callee.signature
                                    };
                                    List<String> encoded = new ArrayList<>();
                                    for (String item : data) {
                                        encoded.add(encode(item));
                                    }
                                    if (edges.size() >= MAX_EDGES) {
                                        truncated[0] = true;
                                    } else {
                                        edges.add("EDGE\t" + String.join("\t", encoded));
                                    }
                                }
                            }
                        }
                        return super.visitMethodInvocation(node, unused);
                    }
                }.scan(unit, null);
            }

            long errors = diagnostics.getDiagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR).count();
            System.out.println("META\t" + sources.size() + "\t" + errors
                + "\t" + declarations.size() + "\t" + (truncated[0] ? "1" : "0"));
            List<String> ordered = new ArrayList<>(edges);
            Collections.sort(ordered);
            for (String edge : ordered) {
                System.out.println(edge);
            }
        }
    }
}
