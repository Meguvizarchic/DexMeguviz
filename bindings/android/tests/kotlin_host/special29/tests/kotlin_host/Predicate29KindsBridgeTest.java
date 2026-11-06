package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Host JNI test of kind and owner flags, with scope kept explicitly incomplete. */
public final class Predicate29KindsBridgeTest {
    private static void check(boolean condition, String label) {
        if (!condition) throw new AssertionError(label);
    }

    private static void compare(NativeEngine.Snapshot snapshot, String label,
                                MethodPredicate predicate, String... expected) {
        MethodQuery query = new MethodQuery(predicate, QueryIntent.ENUMERATE, 4096, 100000000L);
        NativeEngine.QueryResult actual = QueryExecution.INSTANCE.execute(snapshot, query);
        NativeEngine.QueryResult direct = snapshot.queryMethods(query.toQueryIrJson().getBytes(StandardCharsets.UTF_8));
        check(actual.executionStatus == 0 && actual.coverage == 1, label + " status and scope");
        check(actual.queryId.equals(direct.queryId) && actual.snapshotId.equals(direct.snapshotId), label + " identities");
        Set<String> names = new HashSet<>();
        for (int i = 0; i < actual.candidateCount(); ++i) {
            NativeEngine.MethodCandidate candidate = actual.candidate(i);
            check(candidate.sourceIndex == 0 && candidate.inputIndex == 0, label + " origin");
            check(names.add(candidate.name), label + " duplicate");
        }
        check(names.equals(new HashSet<>(Arrays.asList(expected))), label + " candidates: " + names);
        check(actual.candidateCount() == direct.candidateCount(), label + " direct count");
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 1, "fixture argument");
        try (NativeEngine.Snapshot snapshot = NativeEngine.openRawDex(Files.readAllBytes(Path.of(args[0])), "kind-fixture")) {
            MethodPredicate.Companion p = MethodPredicate.Companion;
            compare(snapshot, "constructor", p.constructor(), "<init>");
            compare(snapshot, "clinit", p.classInitializer(), "<clinit>");
            compare(snapshot, "normal", p.normalMethod(), "alpha", "beta");
            compare(snapshot, "exact public", p.ownerFlags(RawFlagOperation.EXACT, new RawDexFlags(1)), "<clinit>", "<init>", "alpha");
            compare(snapshot, "exact final", p.ownerFlags(RawFlagOperation.EXACT, new RawDexFlags(17)), "beta");
            compare(snapshot, "exact absent", p.ownerFlags(RawFlagOperation.EXACT, new RawDexFlags(0)));
            compare(snapshot, "any final", p.ownerFlags(RawFlagOperation.ANY, new RawDexFlags(16)), "beta");
            compare(snapshot, "any absent", p.ownerFlags(RawFlagOperation.ANY, new RawDexFlags(32)));
            compare(snapshot, "any zero", p.ownerFlags(RawFlagOperation.ANY, new RawDexFlags(0)));
            compare(snapshot, "contains zero", p.ownerFlags(RawFlagOperation.CONTAINS, new RawDexFlags(0)), "<clinit>", "<init>", "alpha", "beta");
        }
        System.out.println("PASS 10 method-kind and owner-flags cases through Windows JNI");
    }
}
