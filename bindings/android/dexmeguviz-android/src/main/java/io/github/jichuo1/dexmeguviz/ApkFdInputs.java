package io.github.jichuo1.dexmeguviz;

import java.util.HashSet;

/** Shared early checks; native core repeats all security and budget checks. */
final class ApkFdInputs {
    private ApkFdInputs() {}
    static void hashes(String[] values,int count){
        if(values==null)return;if(values.length!=count)throw new IllegalArgumentException("digest count differs");
        for(String value:values)if(value!=null){if(value.length()!=64)throw new IllegalArgumentException("invalid SHA-256");
            for(int i=0;i<64;i++){char c=value.charAt(i);if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))throw new IllegalArgumentException("invalid SHA-256");}}
    }
    static void validate(int[] fds,long[] offsets,long[] lengths,String[] slots,boolean[] allow,String[] expected,ApkFdLimits limits){
        if(fds==null||offsets==null||lengths==null||slots==null||allow==null||limits==null)throw new NullPointerException("fd sources and limits are required");
        int count=fds.length;if(count<1||count>8||offsets.length!=count||lengths.length!=count||slots.length!=count||allow.length!=count)throw new IllegalArgumentException("invalid fd source count");
        hashes(expected,count);HashSet<String> keys=new HashSet<>();long total=0;
        for(int i=0;i<count;i++){
            long offset=offsets[i],length=lengths[i];String slot=slots[i];
            if(fds[i]<0||offset<0||length<0||offset>Long.MAX_VALUE-length)throw new IllegalArgumentException("invalid fd range");
            if(slot==null||slot.isEmpty()||slot.length()>128)throw new IllegalArgumentException("invalid slot");
            for(int j=0;j<slot.length();j++)if(slot.charAt(j)<0x21||slot.charAt(j)>0x7e)throw new IllegalArgumentException("invalid slot");
            if(!keys.add(slot))throw new IllegalArgumentException("duplicate slot");
            if(length>limits.maxArchiveBytes||length>limits.maxSourceBytes||length>limits.maxTotalArchiveBytes-total)throw new IllegalArgumentException("APK input budget exceeded");
            total+=length;
        }
    }
}
