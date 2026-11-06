package io.github.jichuo1.dexmeguviz.precompute;

final class Budget {
    final PrecomputedCandidates.Limits limits;final long started=System.nanoTime();long work,materialized,textUnits;
    Budget(PrecomputedCandidates.Limits limits){this.limits=limits;check();}
    void check(){if(limits.cancelled!=null&&limits.cancelled.getAsBoolean())throw new PrecomputedCandidates.Failure("Cancelled","offline candidate verification cancelled");if(limits.deadlineAfterMs>0&&(System.nanoTime()-started)/1000000L>=limits.deadlineAfterMs)throw new PrecomputedCandidates.Failure("Deadline","offline candidate deadline");}
    void charge(long n){check();if(n<0||n>limits.maxLocalWork-work)throw new PrecomputedCandidates.Failure("BudgetExceeded","local verification work");work+=n;}
    void retain(long n){check();if(n<0||n>limits.maxMaterializedDexBytes-materialized)throw new PrecomputedCandidates.Failure("BudgetExceeded","cumulative materialized DEX bytes");materialized+=n;}
    void text(long n){check();if(n<0||n>8388608L-textUnits)throw new PrecomputedCandidates.Failure("BudgetExceeded","aggregate text units");textUnits+=n;}
}
