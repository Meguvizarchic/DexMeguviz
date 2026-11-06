package io.github.jichuo1.dexmeguviz;

/** Explicit core-account limits for fd-backed APK inputs; they do not bound RSS or wall time. */
public final class ApkFdLimits {
    public static final long MAX_OWNED_BYTES=1L<<30, MAX_SOURCE_BYTES=512L<<20;
    public final long ownedBytes,maxSourceBytes,maxArchiveBytes,maxTotalArchiveBytes,maxDexBytes,maxTotalDexBytes;
    public final int maxEntries;
    public final long maxCentralDirectoryBytes,maxTotalNameBytes;
    public ApkFdLimits(long ownedBytes,long maxSourceBytes,long maxArchiveBytes,long maxTotalArchiveBytes,
            long maxDexBytes,long maxTotalDexBytes,int maxEntries,long maxCentralDirectoryBytes,long maxTotalNameBytes){
        if(ownedBytes<1||ownedBytes>MAX_OWNED_BYTES||maxSourceBytes<1||maxSourceBytes>MAX_SOURCE_BYTES||
                maxArchiveBytes<1||maxArchiveBytes>maxSourceBytes||maxTotalArchiveBytes<1||maxTotalArchiveBytes>8L*MAX_SOURCE_BYTES||
                maxDexBytes<1||maxDexBytes>maxSourceBytes||maxTotalDexBytes<1||maxTotalDexBytes>ownedBytes||
                maxEntries<1||maxEntries>100000||maxCentralDirectoryBytes<1||maxCentralDirectoryBytes>(16L<<20)||
                maxTotalNameBytes<1||maxTotalNameBytes>(8L<<20))throw new IllegalArgumentException("invalid fd source limits");
        this.ownedBytes=ownedBytes;this.maxSourceBytes=maxSourceBytes;this.maxArchiveBytes=maxArchiveBytes;
        this.maxTotalArchiveBytes=maxTotalArchiveBytes;this.maxDexBytes=maxDexBytes;this.maxTotalDexBytes=maxTotalDexBytes;
        this.maxEntries=maxEntries;this.maxCentralDirectoryBytes=maxCentralDirectoryBytes;this.maxTotalNameBytes=maxTotalNameBytes;
    }
    long[] nativeValues(){return new long[]{ownedBytes,maxSourceBytes,maxArchiveBytes,maxTotalArchiveBytes,maxDexBytes,maxTotalDexBytes,maxEntries,maxCentralDirectoryBytes,maxTotalNameBytes};}
}
