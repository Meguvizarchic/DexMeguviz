package io.github.jichuo1.dexmeguviz;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicReference;

/** Parallel selected-only QueryIR scans over explicitly trusted immutable APK inputs. */
public final class ParallelFastDexQuery {
    private ParallelFastDexQuery() {}

    /**
     * Scan one APK. Every result retains its input slot and DEX occurrence.
     * APK immutability and DEX validity/sortedness are caller assertions;
     * selected-only results are not strict source coverage or ART authentication.
     */
    public static TrustedApkDexSource.Result<FastDexQuery.Result> query(
            File apk, String sourceSlot, TrustedApkDexSource.Policy policy,
            TrustedApkDexSource.Limits sourceLimits, FastDexQuery.InputAssumption assumption,
            FastDexQuery.Limits queryLimits, byte[][] queries, boolean[] captureCalls) throws Exception {
        Objects.requireNonNull(sourceLimits, "sourceLimits");
        TrustedApkDexSource.SourceSetLimits setLimits = new TrustedApkDexSource.SourceSetLimits(
                sourceLimits, 1, sourceLimits.maxSources, sourceLimits.maxArchiveBytes, sourceLimits.maxTotalDexBytes);
        return queryAll(Collections.singletonList(new TrustedApkDexSource.Input(apk, sourceSlot, sourceLimits.allowNoDex)),
                policy, setLimits, assumption, queryLimits, queries, captureCalls).inputs.get(0);
    }

    /**
     * Scans an ordered APK set with one bounded worker pool. Each active worker
     * owns and reuses a compiled plan; the native session limit is shared with
     * other FastDexQuery users in the process, so competing calls may fail.
     * Results are returned only after all sources succeed and retain each lane's
     * partial coverage, status, unknown count and result-limit information.
     * Callers must interpret these before making a business or absence decision.
     *
     * Query arrays are copied before work begins; callers must not mutate them
     * while this call is running. The caller guarantees each APK is immutable
     * during this call and each selected DEX is valid with sorted ID
     * tables. Input ZIP/DEX limits and query-output limits do not bound all Java,
     * native or VM allocations. Work is synchronous; cleanup waits for running
     * JNI work because it cannot be forcibly interrupted safely.
     */
    public static TrustedApkDexSource.SourceSetResult<FastDexQuery.Result> queryAll(
            List<TrustedApkDexSource.Input> inputs, TrustedApkDexSource.Policy policy,
            TrustedApkDexSource.SourceSetLimits sourceLimits, FastDexQuery.InputAssumption assumption,
            FastDexQuery.Limits queryLimits, byte[][] queries, boolean[] captureCalls) throws Exception {
        Objects.requireNonNull(inputs, "inputs");
        Objects.requireNonNull(sourceLimits, "sourceLimits");
        Objects.requireNonNull(assumption, "assumption");
        Objects.requireNonNull(queryLimits, "queryLimits");
        Objects.requireNonNull(queries, "queries");
        Objects.requireNonNull(captureCalls, "captureCalls");
        if (assumption != FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX ||
                policy != TrustedApkDexSource.Policy.TRUSTED_IMMUTABLE_APK)
            throw new IllegalArgumentException("explicit trusted input assumptions are required");
        if (queries.length < 1 || queries.length > 16 || captureCalls.length != queries.length ||
                sourceLimits.perInput.workers > 32)
            throw new IllegalArgumentException("invalid query count or worker limit");
        byte[][] immutableQueries = new byte[queries.length][];
        for (int i = 0; i < queries.length; ++i)
            immutableQueries[i] = Objects.requireNonNull(queries[i], "query").clone();
        boolean[] immutableCalls = captureCalls.clone();
        List<TrustedApkDexSource.Input> immutableInputs = Collections.unmodifiableList(new ArrayList<>(inputs));
        ConcurrentLinkedQueue<FastDexQuery.Plans> sessions = new ConcurrentLinkedQueue<>();
        Throwable primary = null;
        try {
            // Validate plans even for a resource-only source set. The first
            // worker reuses the validated plan instead of compiling it again.
            FastDexQuery.Plans initial = FastDexQuery.compile(immutableQueries, immutableCalls);
            try { sessions.add(initial); }
            catch (RuntimeException | Error failure) {
                try { initial.close(); } catch (RuntimeException | Error closeFailure) { failure.addSuppressed(closeFailure); }
                throw failure;
            }
            AtomicReference<FastDexQuery.Plans> initialAvailable = new AtomicReference<>(initial);
            ThreadLocal<FastDexQuery.Plans> local = new ThreadLocal<FastDexQuery.Plans>() {
                @Override protected FastDexQuery.Plans initialValue() {
                    FastDexQuery.Plans first = initialAvailable.getAndSet(null);
                    if (first != null) return first;
                    FastDexQuery.Plans plans = FastDexQuery.compile(immutableQueries, immutableCalls);
                    try { sessions.add(plans); return plans; }
                    catch (RuntimeException | Error failure) {
                        try { plans.close(); } catch (RuntimeException | Error closeFailure) { failure.addSuppressed(closeFailure); }
                        throw failure;
                    }
                }
            };
            return TrustedApkDexSource.mapAll(immutableInputs, policy, sourceLimits,
                    (entry, bytes) -> local.get().scan(bytes, assumption, queryLimits));
        } catch (Exception | Error failure) {
            primary = failure;
            throw failure;
        } finally {
            Throwable closeFailure = null;
            for (FastDexQuery.Plans plans : sessions) {
                try { plans.close(); }
                catch (RuntimeException | Error failure) {
                    if (closeFailure == null) closeFailure = failure;
                    else closeFailure.addSuppressed(failure);
                }
            }
            if (closeFailure != null) {
                if (primary != null) primary.addSuppressed(closeFailure);
                else if (closeFailure instanceof RuntimeException) throw (RuntimeException) closeFailure;
                else throw (Error) closeFailure;
            }
        }
    }
}
