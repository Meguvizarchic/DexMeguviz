package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Host JVM check of the snapshot-bound Kotlin method-v1 bridge. */
public final class KotlinBridgeTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    public static void main(String[] args) throws Exception {
        byte[] dex = Files.readAllBytes(Path.of(args[0]));
        MethodPredicate p = MethodPredicate.Companion.text(MethodTextField.NAME, TextOperation.EXACT, "locate", false);
        MethodQuery q = new MethodQuery(p, QueryIntent.UNIQUE, 4096, 100000000L);
        check(!QueryExecution.INSTANCE.getSupported(), "legacy entry-point support");
        try { QueryExecution.INSTANCE.execute(q); throw new AssertionError("snapshot-free entry accepted"); }
        catch (UnsupportedOperationException expected) { /* legacy entry remains unsupported */ }
        NativeEngine.QueryResult copied;
        NativeEngine.Snapshot snapshot = NativeEngine.openRawDex(dex, "kotlin-bridge");
        try (snapshot) {
            copied = QueryExecution.INSTANCE.execute(snapshot, q);
            NativeEngine.QueryResult direct = snapshot.queryMethods(q.toQueryIrJson().getBytes(StandardCharsets.UTF_8));
            check(copied.executionStatus == 0 && copied.coverage == 1 && copied.decision == 1, "incomplete Unique");
            check(copied.queryId.equals(direct.queryId) && copied.snapshotId.equals(direct.snapshotId), "identities");
            check(copied.candidateCount() == 1 && copied.candidate(0).name.equals("locate"), "candidate");
            MethodQuery exists = new MethodQuery(p, QueryIntent.EXISTS, 4096, 100000000L);
            NativeEngine.QueryResult found = QueryExecution.INSTANCE.execute(snapshot, exists);
            check(found.executionStatus == 0 && found.coverage == 1 && found.decision == 3 && found.candidateCount() == 1, "Exists witness");
            MethodQuery limited = new MethodQuery(MethodPredicate.Companion.constant(true), QueryIntent.ENUMERATE, 1, 100000000L);
            NativeEngine.QueryResult partial = QueryExecution.INSTANCE.execute(snapshot, limited);
            check(partial.executionStatus == 4 && partial.coverage == 1 && partial.reason == 4 && partial.candidateCount() == 1, "result limit");
            try { QueryExecution.INSTANCE.execute(snapshot, new MethodQuery(p, QueryIntent.ENUMERATE, 4097, 100000000L));
                  throw new AssertionError("bridge result limit accepted"); }
            catch (NativeEngine.NativeFailure expected) { check(expected.status == 4, "bridge result limit status"); }
            try { QueryExecution.INSTANCE.execute(snapshot, new MethodQuery(p, QueryIntent.ENUMERATE, 4096, 100000001L));
                  throw new AssertionError("bridge work limit accepted"); }
            catch (NativeEngine.NativeFailure expected) { check(expected.status == 4, "bridge work limit status"); }
            try { QueryExecution.INSTANCE.execute(snapshot, new MethodQuery(p, QueryIntent.ENUMERATE, 4096, 1));
                  throw new AssertionError("core work budget unexpectedly succeeded"); }
            catch (NativeEngine.NativeFailure expected) { check(expected.status == 4, "core work budget status"); }
            String unusual = new String(new char[]{'A', '\0', '\ud800', 'X', '\udfff'});
            MethodPredicate unusualPredicate = MethodPredicate.Companion.text(MethodTextField.NAME, TextOperation.EXACT, unusual, false);
            MethodQuery unusualQuery = new MethodQuery(unusualPredicate, QueryIntent.EXISTS, 4096, 100000000L);
            NativeEngine.QueryResult unusualResult = QueryExecution.INSTANCE.execute(snapshot, unusualQuery);
            check(unusualResult.executionStatus == 0 && unusualResult.coverage == 1 && unusualResult.decision == 1 && unusualResult.candidateCount() == 0,
                  "NUL and isolated-surrogate input remains undetermined");
            MethodPredicate unusualValue = MethodPredicate.Companion.textValue(MethodTextField.NAME, TextOperation.EXACT, unusual, false);
            NativeEngine.QueryResult valueResult = QueryExecution.INSTANCE.execute(snapshot,
                new MethodQuery(unusualValue, QueryIntent.EXISTS, 4096, 100000000L));
            String prefix = "{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":{\"name\":{\"op\":\"exact\",";
            String suffix = ",\"ascii_case_insensitive\":false}},\"intent\":\"exists\",\"max_results\":4096,\"max_work\":100000000}";
            NativeEngine.QueryResult numeric = snapshot.queryMethods((prefix + "\"u16\":[65,0,55296,88,57343]" + suffix).getBytes(StandardCharsets.UTF_8));
            NativeEngine.QueryResult escaped = snapshot.queryMethods((prefix + "\"value\":\"A\\u0000\\ud800X\\udfff\"" + suffix).getBytes(StandardCharsets.UTF_8));
            check(unusualResult.queryId.equals(valueResult.queryId) && unusualResult.queryId.equals(numeric.queryId) && unusualResult.queryId.equals(escaped.queryId), "UTF-16 QueryID equivalence");
            check(unusualResult.executionStatus == valueResult.executionStatus && unusualResult.coverage == valueResult.coverage &&
                  unusualResult.decision == valueResult.decision && unusualResult.candidateCount() == valueResult.candidateCount(), "UTF-16 Kotlin encoding equivalence");
            check(unusualResult.executionStatus == numeric.executionStatus && unusualResult.coverage == numeric.coverage &&
                  unusualResult.decision == numeric.decision && unusualResult.candidateCount() == numeric.candidateCount(), "UTF-16 result equivalence");
        }
        check(copied.candidate(0).name.equals("locate"), "copied result after close");
        try { QueryExecution.INSTANCE.execute(snapshot, q); throw new AssertionError("closed snapshot accepted"); }
        catch (IllegalStateException expected) { /* snapshot is closed */ }
        byte[] secondDex = Files.readAllBytes(Path.of(args[1]));
        try (NativeEngine.SourceSetSnapshot set = NativeEngine.openRawDexSet(new byte[][]{dex, secondDex}, new String[]{"base", "split"})) {
            NativeEngine.SourceSetInfo info = set.info();
            check(!info.sourceScopeComplete && info.sourceCount() == 2, "incomplete two-source scope");
            MethodPredicate secondName = MethodPredicate.Companion.text(MethodTextField.NAME, TextOperation.EXACT, "uses", false);
            MethodQuery secondQuery = new MethodQuery(secondName, QueryIntent.UNIQUE, 4096, 100000000L);
            NativeEngine.QueryResult second = QueryExecution.INSTANCE.execute(set, secondQuery);
            check(second.executionStatus == 0 && second.coverage == 1 && second.decision == 1 && second.candidateCount() == 1, "multi-source result");
            NativeEngine.MethodCandidate candidate = second.candidate(0);
            check(candidate.sourceIndex == 1 && candidate.inputIndex == 1 && candidate.sourceSlot.equals("split") &&
                  candidate.occurrenceId.equals(info.source(1).occurrenceId), "multi-source origin");
            MethodPredicate use = MethodPredicate.Companion.usesString(TextOperation.EXACT, "code-use-q03", false);
            MethodPredicate count = MethodPredicate.Companion.parameterCount(0);
            MethodPredicate conditions = MethodPredicate.Companion.all(use, count, MethodPredicate.Companion.normalMethod());
            MethodQuery bodyQuery = new MethodQuery(conditions, QueryIntent.ENUMERATE, 4096, 100000000L);
            NativeEngine.QueryResult body = QueryExecution.INSTANCE.execute(set, bodyQuery);
            NativeEngine.QueryResult directBody = set.queryMethods(bodyQuery.toQueryIrJson().getBytes(StandardCharsets.UTF_8));
            check(body.executionStatus == 0 && body.coverage == 1 && body.candidateCount() == 1 &&
                  body.candidate(0).name.equals("uses") && body.candidate(0).sourceIndex == 1 &&
                  body.queryId.equals(directBody.queryId), "Kotlin body use and parameter count through JNI");
            MethodPredicate poolOnly = MethodPredicate.Companion.usesString(TextOperation.EXACT, "annotation-only-q03", false);
            NativeEngine.QueryResult excluded = QueryExecution.INSTANCE.execute(set,
                new MethodQuery(poolOnly, QueryIntent.ENUMERATE, 4096, 100000000L));
            check(excluded.executionStatus == 0 && excluded.coverage == 1 && excluded.candidateCount() == 0,
                  "string pool and annotation presence is not method body use");
        }
        System.out.println("PASS Kotlin snapshot bridge, incomplete scope and UTF-16 query input");
    }
}
