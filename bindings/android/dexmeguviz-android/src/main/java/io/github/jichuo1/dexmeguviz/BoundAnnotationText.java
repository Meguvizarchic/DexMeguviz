package io.github.jichuo1.dexmeguviz;

import java.util.Objects;

/** Text matching tied to one copied result and one live static snapshot handle. */
public final class BoundAnnotationText {
    private final AnnotationResult result;
    private final Object snapshot;
    private final boolean sourceSet;
    private final int maxUtf16Units;

    private BoundAnnotationText(AnnotationResult result,Object snapshot,boolean sourceSet,int maxUtf16Units) {
        if(result==null || snapshot==null) throw new NullPointerException("result and snapshot are required");
        if(maxUtf16Units<1 || maxUtf16Units>1048576) throw new IllegalArgumentException("invalid text limit");
        this.result=result;this.snapshot=snapshot;this.sourceSet=sourceSet;this.maxUtf16Units=maxUtf16Units;
        synchronized(snapshot) { verifyIdentity(); }
    }
    /** Binds one static source; identical metadata may also arise from another opened object. */
    public static BoundAnnotationText bind(AnnotationResult result,NativeEngine.Snapshot snapshot,int maxUtf16Units) {
        return new BoundAnnotationText(result,snapshot,false,maxUtf16Units);
    }
    /** Uses the source index carried by the copied result, never a caller-selected index. */
    public static BoundAnnotationText bind(AnnotationResult result,NativeEngine.SourceSetSnapshot snapshot,int maxUtf16Units) {
        return new BoundAnnotationText(result,snapshot,true,maxUtf16Units);
    }
    /** Compare an item from the bound result using bounded, source-local STRING or TYPE resolution. */
    public int text(int itemIndex,String descriptor,int visibility,String name,int kind,String expected,
                    int maxElements,EncodedValue.Limits limits) {
        synchronized(snapshot) {
            verifyIdentity();
            return AnnotationMatcher.text(result.item(itemIndex),descriptor,visibility,name,kind,expected,
                this::resolve,maxElements,limits);
        }
    }
    private String resolve(int kind,long index) {
        if(sourceSet) {
            var handle=(NativeEngine.SourceSetSnapshot)snapshot;int sourceIndex=(int)result.sourceIndex;
            return kind==EncodedValue.STRING ? DexSourceExport.stringAt(handle,sourceIndex,index,maxUtf16Units)
                    : DexSourceExport.typeAt(handle,sourceIndex,index,maxUtf16Units);
        }
        var handle=(NativeEngine.Snapshot)snapshot;
        return kind==EncodedValue.STRING ? DexSourceExport.stringAt(handle,index,maxUtf16Units)
                : DexSourceExport.typeAt(handle,index,maxUtf16Units);
    }
    private void verifyIdentity() {
        if(!sourceSet) {
            var info=((NativeEngine.Snapshot)snapshot).info();
            if(result.sourceIndex!=0 || result.inputIndex!=0 || !result.snapshotId.equals(info.snapshotId)
                    || !result.sourceSha256.equals(info.sourceSha256) || result.sourceBytes!=info.sourceBytes)
                throw new IllegalArgumentException("annotation result and snapshot identity differ");
            return;
        }
        var info=((NativeEngine.SourceSetSnapshot)snapshot).info();
        if(!result.snapshotId.equals(info.snapshotId) || result.sourceIndex>=info.sourceCount())
            throw new IllegalArgumentException("annotation result and source set identity differ");
        var source=info.source((int)result.sourceIndex);
        long entry=source.archiveEntryIndex<0 ? 0xffffffffL : source.archiveEntryIndex;
        if(result.sourceIndex!=source.sourceIndex || result.inputIndex!=source.inputIndex
                || !result.slot.equals(source.slot) || !result.sourceSha256.equals(source.sourceSha256)
                || !result.contentId.equals(source.contentId) || !result.occurrenceId.equals(source.occurrenceId)
                || !result.logicalDexId.equals(source.logicalDexId) || result.sourceBytes!=source.sourceBytes
                || result.archiveEntryIndex!=entry || !Objects.equals(result.archiveEntryName,source.archiveEntryName))
            throw new IllegalArgumentException("annotation result and source identity differ");
    }
}
