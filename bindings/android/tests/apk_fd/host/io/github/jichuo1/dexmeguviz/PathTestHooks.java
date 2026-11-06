package io.github.jichuo1.dexmeguviz;
public final class PathTestHooks {
 private PathTestHooks(){}
 public static native void arm();
 public static native int entered();
 public static native int opened();
 public static native void release();
 public static native void failNextClose();
}
