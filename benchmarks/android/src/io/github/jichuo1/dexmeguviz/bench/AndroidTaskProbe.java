package io.github.jichuo1.dexmeguviz.bench;
import android.os.Debug;
import android.os.SystemClock;
/** Android reader for the current process only. No permissions or cross-process access. */
public final class AndroidTaskProbe {
    private AndroidTaskProbe(){}
    public static TaskProbe create(int maxSamples){
        final Debug.MemoryInfo info=new Debug.MemoryInfo();
        return new TaskProbe(SystemClock::elapsedRealtimeNanos,()->{
            Debug.getMemoryInfo(info);int kb=info.getTotalPss();
            if(kb<=0)throw new IllegalStateException("PSS unavailable");
            return Math.multiplyExact((long)kb,1024L);
        },maxSamples);
    }
}
