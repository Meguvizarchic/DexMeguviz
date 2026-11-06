package io.github.jichuo1.dexmeguviz.examples;

import android.content.pm.ApplicationInfo;
import io.github.jichuo1.dexmeguviz.AndroidApkSources;
import io.github.jichuo1.dexmeguviz.ApkFdLimits;
import io.github.jichuo1.dexmeguviz.ApkMetadataPlan;
import io.github.jichuo1.dexmeguviz.NativeEngine;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/** Demonstration only: the host supplies a background worker and explicitly chosen limits. */
public final class ApkPlanExample {
    private ApkPlanExample() {}

    public static final class Report {
        public final int inputCount, sourceCount;
        public final NativeEngine.QueryResult methods;
        private Report(int inputCount,int sourceCount,NativeEngine.QueryResult methods) {
            this.inputCount=inputCount;this.sourceCount=sourceCount;this.methods=methods;
        }
    }

    /** Metadata is copied before scheduling; do not mutate info or arrays during this call. */
    public static Future<Report> submit(ExecutorService background,ApplicationInfo info,
            boolean baseAllowNoDex,boolean[] splitAllowNoDex,String[] expectedSha256,ApkFdLimits limits) {
        if(background==null)throw new NullPointerException("background worker is required");
        final ApkMetadataPlan plan=AndroidApkSources.plan(info,baseAllowNoDex,splitAllowNoDex);
        final String[] expected=expectedSha256==null?null:expectedSha256.clone();
        return background.submit(() -> {
            try(AndroidApkSources.Opened opened=AndroidApkSources.open(plan,expected,limits)) {
                NativeEngine.SourceSetInfo infoCopy=opened.snapshot.info();
                if(infoCopy.sourceScopeComplete)throw new IllegalStateException("unexpected complete source scope");
                // Ask whether at least one method definition is observed, not for all methods.
                byte[] query=("{\"schema_version\":1,\"relation\":\"method_defs\","
                        +"\"where\":true,\"intent\":\"exists\"}").getBytes(StandardCharsets.UTF_8);
                NativeEngine.QueryResult result=opened.snapshot.queryMethods(query);
                if(result.executionStatus!=0||result.coverage!=1)
                    throw new IllegalStateException("query status="+result.executionStatus+", reason="+result.reason+", coverage="+result.coverage);
                return new Report(infoCopy.inputCount(),infoCopy.sourceCount(),result);
            }
        });
    }
}
