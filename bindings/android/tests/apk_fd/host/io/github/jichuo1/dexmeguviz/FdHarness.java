package io.github.jichuo1.dexmeguviz;
public final class FdHarness {
 private FdHarness(){}
 public static native int open(String path);
 public static native long seek(int fd,long offset);
 public static native long position(int fd);
 public static native int close(int fd);
 public static native int handleCount();
}
