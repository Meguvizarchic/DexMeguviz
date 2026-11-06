package io.github.jichuo1.dexmeguviz;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class JniUtf16Test {
    private static final String OWNER = "Lsample/Owner\uD83D\uDE00;";
    private static final String NAME = "method\uD83D\uDE00";
    private static final String PROTOTYPE = "(Lsample/Arg\uD801\uDC00;)V";
    private static void check(boolean ok, String what) { if (!ok) throw new AssertionError(what); }
    private static byte[] query(String intent, String predicate) {
        return ("{\"schema_version\":1,\"relation\":\"method_defs\",\"intent\":\"" + intent + "\",\"where\":" + predicate + "}")
            .getBytes(StandardCharsets.US_ASCII);
    }
    private static String nameQuery(String operation, String valueJson) {
        return "{\"name\":{\"op\":\"" + operation + "\"," + valueJson + "}}";
    }
    private static void absentInIncompleteScope(NativeEngine.Snapshot snapshot, String valueJson) {
        var result = snapshot.queryMethods(query("exists", nameQuery("contains", valueJson)));
        check(result.executionStatus == 0 && result.coverage == 1 && result.decision == 1 &&
              result.reason == 5 && result.candidateCount() == 0, "absence in incomplete scope");
    }
    private static void containedCodeUnit(NativeEngine.Snapshot snapshot, int unit) {
        var result = snapshot.queryMethods(query("exists", nameQuery("contains", "\"u16\":[" + unit + "]")));
        check(result.executionStatus == 0 && result.coverage == 1 && result.decision == 3 &&
              result.candidateCount() == 1 && result.candidate(0).name.equals(NAME), "UTF-16 code-unit contains");
    }
    public static void main(String[] args) throws Exception {
        check(args.length == 1, "fixture path required");
        byte[] dex = Files.readAllBytes(Path.of(args[0]));
        check(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(dex))
            .equals("d9eac2a91992305eb36bc7fdfde2ad65299ea564a96dbd055c11ad3437c4b575"), "fixture digest");
        NativeEngine.QueryResult retained;
        try (NativeEngine.Snapshot snapshot = NativeEngine.openRawDex(dex, "supplementary")) {
            check(!snapshot.info().sourceScopeComplete, "single input scope must be incomplete");
            String raw = nameQuery("exact", "\"u16\":[109,101,116,104,111,100,55357,56832]");
            String escaped = nameQuery("exact", "\"value\":\"method\\ud83d\\ude00\"");
            retained = snapshot.queryMethods(query("unique", raw));
            var same = snapshot.queryMethods(query("unique", escaped));
            check(retained.executionStatus == 0 && retained.coverage == 1 && retained.decision == 1 &&
                  retained.reason == 5 && retained.candidateCount() == 1, "unique incomplete result");
            check(retained.queryId.equals(same.queryId) && same.candidateCount() == 1, "equivalent QueryID");
            var candidate = retained.candidate(0);
            check(candidate.methodIndex == 0 && candidate.accessFlags == 0x109 && candidate.declarationOffset == 297 && candidate.codeOffset == 0, "native method values");
            check(candidate.name.equals(NAME) && candidate.owner.equals(OWNER) && candidate.prototype.equals(PROTOTYPE), "copied UTF-16 fields");
            check(candidate.name.length() == 8 && candidate.name.charAt(6) == '\uD83D' && candidate.name.charAt(7) == '\uDE00', "supplementary name units");
            check(candidate.prototype.charAt(12) == '\uD801' && candidate.prototype.charAt(13) == '\uDC00', "supplementary type units");
            var owner = snapshot.queryMethods(query("exists", "{\"owner\":{\"op\":\"exact\",\"value\":\"Lsample/Owner\\ud83d\\ude00;\"}}"));
            check(owner.coverage == 1 && owner.decision == 3 && owner.candidateCount() == 1, "supplementary owner exact");
            var proto = snapshot.queryMethods(query("exists", "{\"prototype\":{\"op\":\"exact\",\"value\":\"(Lsample/Arg\\ud801\\udc00;)V\"}}"));
            check(proto.coverage == 1 && proto.decision == 3 && proto.candidateCount() == 1, "supplementary prototype exact");
            // Lone surrogate query units are allowed as text, but not as DEX member names.
            containedCodeUnit(snapshot, 55357);
            containedCodeUnit(snapshot, 56832);
            absentInIncompleteScope(snapshot, "\"u16\":[0]");
            absentInIncompleteScope(snapshot, "\"value\":\"\\u0000\"");
            absentInIncompleteScope(snapshot, "\"u16\":[55296]");
            absentInIncompleteScope(snapshot, "\"u16\":[56320]");
            absentInIncompleteScope(snapshot, "\"value\":\"\\ud800\"");
            absentInIncompleteScope(snapshot, "\"value\":\"\\udc00\"");
            var projected = snapshot.queryMethods(("{\"schema_version\":1,\"relation\":\"method_defs\",\"where\":" + raw + ",\"projection\":[\"name\"]}").getBytes(StandardCharsets.US_ASCII));
            check(projected.candidateCount() == 1 && projected.candidate(0).name.equals(NAME) &&
                  projected.candidate(0).owner == null && projected.candidate(0).prototype == null, "projection");
        }
        check(retained.candidate(0).name.equals(NAME) && retained.candidate(0).owner.equals(OWNER) &&
              retained.candidate(0).prototype.equals(PROTOTYPE), "copied values after close");
        System.out.println("PASS host JNI UTF-16: valid supplementary names, exact/contains code units, incomplete scope and copied values");
    }
}
