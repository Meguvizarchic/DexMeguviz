package io.github.jichuo1.dexmeguviz;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public final class JniSnapshotTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    private static void failureStatus(int status, Runnable action) {
        try { action.run(); throw new AssertionError("expected NativeFailure " + status); }
        catch (NativeEngine.NativeFailure error) { check(error.status == status, "wrong status " + error.status); }
    }
    private static void invalidSlot(byte[] bytes, String slot) {
        try { NativeEngine.openRawDex(bytes, slot); throw new AssertionError("invalid slot accepted"); }
        catch (IllegalArgumentException expected) { /* expected */ }
    }
    public static void main(String[] args) throws Exception {
        check(args.length == 1, "fixture path required");
        byte[] original = Files.readAllBytes(Path.of(args[0]));
        String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original));
        check(sha.equals("dd0e9527dda007481637b6b43393a8239635e85fa006b452092dcc064c3e456f"), "fixture digest");
        check(NativeEngine.abiVersion() == 1 && NativeEngine.capabilities().contains("ordered-source-set"), "ABI probes");
        byte[] input = original.clone();
        NativeEngine.Snapshot snapshot = NativeEngine.openRawDex(input, "slot.one");
        input[0] = 0;
        NativeEngine.SnapshotInfo info = snapshot.info();
        check(info.dexVersion == 35 && info.stringCount == 8 && info.typeCount == 3 && info.classCount == 1, "metadata counts");
        check(info.methodRefCount == 3 && info.methodDefCount == 2 && info.sourceBytes == 448, "member counts");
        check(!info.sourceScopeComplete, "single raw input must not claim complete app scope");
        check(info.sourceSha256.equals(sha), "copied input digest");
        check(info.snapshotId.equals("snapshot:v2:1ed0a5cc54f6d7956fdf50198b46312bacbe4bea83f47ad03a9b73c871c1e4b2"), "independent framed snapshot identity");
        try (NativeEngine.Snapshot same = NativeEngine.openRawDex(original, "slot.one");
             NativeEngine.Snapshot other = NativeEngine.openRawDex(original, "slot.two")) {
            check(same.info().snapshotId.equals(info.snapshotId), "stable identity");
            check(!other.info().snapshotId.equals(info.snapshotId), "slot identity");
        }
        var tokenField = NativeEngine.Snapshot.class.getDeclaredField("token"); tokenField.setAccessible(true);
        long token = tokenField.getLong(snapshot);
        snapshot.close(); snapshot.close();
        try { snapshot.info(); throw new AssertionError("closed snapshot accepted"); }
        catch (IllegalStateException expected) { /* expected */ }
        check(info.sourceSha256.equals(sha) && info.classCount == 1, "info must survive close");
        Method nativeInfo = NativeEngine.class.getDeclaredMethod("nativeSnapshotInfo", long.class); nativeInfo.setAccessible(true);
        try { nativeInfo.invoke(null, token); throw new AssertionError("stale token accepted"); }
        catch (InvocationTargetException error) {
            check(error.getCause() instanceof NativeEngine.NativeFailure && ((NativeEngine.NativeFailure) error.getCause()).status == 7, "stale token error");
        }
        for (String bad : new String[]{"", "with space", "\u0000", "\u00e9", "x".repeat(129)}) invalidSlot(original, bad);
        try { NativeEngine.openRawDex(null, "slot"); throw new AssertionError("null bytes accepted"); }
        catch (NullPointerException expected) { /* expected */ }
        failureStatus(2, () -> NativeEngine.openRawDex(new byte[0], "empty"));
        failureStatus(3, () -> NativeEngine.openRawDex(new byte[]{'P', 'K', 3, 4}, "not-an-apk-entry"));
        failureStatus(4, () -> NativeEngine.openRawDex(new byte[16 * 1024 * 1024 + 1], "too-large"));
        List<NativeEngine.Snapshot> held = new ArrayList<>();
        try {
            for (int i = 0; i < 64; ++i) held.add(NativeEngine.openRawDex(original, "slot." + i));
            failureStatus(4, () -> NativeEngine.openRawDex(original, "over-capacity"));
        } finally { for (NativeEngine.Snapshot item : held) item.close(); }
        try (NativeEngine.Snapshot after = NativeEngine.openRawDex(original, "after-capacity")) {
            check(after.info().sourceSha256.equals(sha), "capacity recovered after close");
        }
        // Hold 48 handles while 24 threads open simultaneously; no more than 16
        // may acquire a live-or-opening permit before any handle is closed.
        List<NativeEngine.Snapshot> prefix = new ArrayList<>();
        ExecutorService openExecutor = Executors.newFixedThreadPool(24);
        CountDownLatch openStart = new CountDownLatch(1), openReady = new CountDownLatch(24), releaseOpens = new CountDownLatch(1);
        try {
            for (int i = 0; i < 48; ++i) prefix.add(NativeEngine.openRawDex(original, "prefix." + i));
            List<Future<Boolean>> futures = new ArrayList<>();
            for (int i = 0; i < 24; ++i) {
                final int index = i;
                futures.add(openExecutor.submit(() -> {
                    NativeEngine.Snapshot value = null;
                    try {
                        openStart.await();
                        try { value = NativeEngine.openRawDex(original, "parallel." + index); }
                        catch (NativeEngine.NativeFailure error) { check(error.status == 4, "parallel admission error"); }
                    } finally { openReady.countDown(); }
                    try { releaseOpens.await(); return value != null; }
                    finally { if (value != null) value.close(); }
                }));
            }
            openStart.countDown(); openReady.await(); releaseOpens.countDown();
            int accepted = 0;
            for (Future<Boolean> future : futures) if (future.get()) ++accepted;
            check(accepted == 16, "concurrent capacity " + accepted);
        } finally {
            releaseOpens.countDown();
            for (NativeEngine.Snapshot value : prefix) value.close();
            openExecutor.shutdownNow();
        }
        NativeEngine.Snapshot concurrent = NativeEngine.openRawDex(original, "concurrent");
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int worker = 0; worker < 3; ++worker) futures.add(executor.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 1000; ++i) {
                        try { check(concurrent.info().sourceSha256.equals(sha), "concurrent info"); }
                        catch (IllegalStateException closed) { break; }
                    }
                } catch (InterruptedException error) { throw new AssertionError(error); }
            }));
            futures.add(executor.submit(() -> { try { start.await(); concurrent.close(); } catch (InterruptedException error) { throw new AssertionError(error); } }));
            start.countDown();
            for (Future<?> future : futures) future.get();
        } finally { concurrent.close(); executor.shutdownNow(); }
        // Exercise the native registry race directly, bypassing the Java instance lock.
        NativeEngine.Snapshot rawRace = NativeEngine.openRawDex(original, "raw-race");
        long raceToken = tokenField.getLong(rawRace);
        Method nativeClose = NativeEngine.class.getDeclaredMethod("nativeClose", long.class); nativeClose.setAccessible(true);
        CountDownLatch raceStart = new CountDownLatch(1);
        ExecutorService raceExecutor = Executors.newFixedThreadPool(4);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int worker = 0; worker < 3; ++worker) futures.add(raceExecutor.submit(() -> {
                try {
                    raceStart.await();
                    for (int i = 0; i < 1000; ++i) {
                        try {
                            Object value = nativeInfo.invoke(null, raceToken);
                            check(((NativeEngine.SnapshotInfo) value).sourceSha256.equals(sha), "registry race info");
                        } catch (InvocationTargetException failure) {
                            check(failure.getCause() instanceof NativeEngine.NativeFailure &&
                                  ((NativeEngine.NativeFailure) failure.getCause()).status == 7, "registry race error");
                            break;
                        }
                    }
                } catch (ReflectiveOperationException | InterruptedException error) { throw new AssertionError(error); }
            }));
            futures.add(raceExecutor.submit(() -> {
                try { raceStart.await(); nativeClose.invoke(null, raceToken); }
                catch (ReflectiveOperationException | InterruptedException error) { throw new AssertionError(error); }
            }));
            raceStart.countDown();
            for (Future<?> future : futures) future.get();
        } finally { rawRace.close(); raceExecutor.shutdownNow(); }
        System.out.println("PASS host JVM JNI snapshot: copied source, identity, errors, capacity, close and concurrent access");
    }
}
