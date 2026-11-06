package io.github.jichuo1.dexmeguviz;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/** Immutable copy of caller-supplied ApplicationInfo fields; not a loader or installation proof. */
public final class ApkMetadataPlan {
    public static final class Entry {
        public final String slot,path,splitName;
        public final boolean allowNoDex;
        private Entry(String slot,String path,String splitName,boolean allowNoDex){this.slot=slot;this.path=path;this.splitName=splitName;this.allowNoDex=allowNoDex;}
    }
    /** Caller declaration only: loader and generation identity do not authenticate sources. */
    public static final class LoaderDeclaration {
        public final ClassLoader loader;
        public final Object generation;
        public LoaderDeclaration(ClassLoader loader,Object generation){if(generation==null)throw new NullPointerException("generation is required");this.loader=loader;this.generation=generation;}
    }
    public final String packageName;
    public final LoaderDeclaration loaderDeclaration;
    private final List<Entry> entries;
    private ApkMetadataPlan(String packageName,LoaderDeclaration loaderDeclaration,List<Entry> entries){this.packageName=packageName;this.loaderDeclaration=loaderDeclaration;this.entries=Collections.unmodifiableList(new ArrayList<>(entries));}
    public List<Entry> entries(){return entries;}
    private static boolean printable(String s){if(s==null||s.isEmpty())return false;for(int i=0;i<s.length();i++)if(s.charAt(i)<0x21||s.charAt(i)>0x7e)return false;return true;}
    private static boolean path(String s){
        if(s==null||s.isEmpty()||s.length()>32767||s.indexOf('\0')>=0)return false;
        File file=new File(s);if(!file.isAbsolute()||file.getName().isEmpty())return false;
        String value=file.getPath();int start=0;
        for(int i=0;i<=value.length();i++){
            if(i==value.length()||value.charAt(i)=='/'||value.charAt(i)==File.separatorChar){
                int size=i-start;if(size==1&&value.charAt(start)=='.')return false;
                if(size==2&&value.charAt(start)=='.'&&value.charAt(start+1)=='.')return false;
                start=i+1;
            }
        }
        return true;
    }
    /** Copies split metadata; every input and allowNoDex decision is explicit. */
    public static ApkMetadataPlan from(String basePath,String[] splitNames,String[] splitPaths,boolean baseAllowNoDex,boolean[] splitAllowNoDex){
        return from(null,null,basePath,splitNames,splitPaths,baseAllowNoDex,splitAllowNoDex);
    }
    /** packageName is observed metadata; loader declaration remains a caller claim. */
    public static ApkMetadataPlan from(String packageName,LoaderDeclaration declaration,String basePath,String[] splitNames,String[] splitPaths,boolean baseAllowNoDex,boolean[] splitAllowNoDex){
        if(packageName!=null&&(packageName.isEmpty()||packageName.length()>1024||packageName.indexOf('\0')>=0))throw new IllegalArgumentException("invalid package name");
        if(!path(basePath))throw new IllegalArgumentException("invalid base path");
        int count=splitNames==null?0:splitNames.length;
        if(count>7||(splitPaths==null?0:splitPaths.length)!=count||(splitAllowNoDex==null?0:splitAllowNoDex.length)!=count)
            throw new IllegalArgumentException("invalid split metadata or input limit");
        String[] names=splitNames==null?new String[0]:splitNames.clone();String[] paths=splitPaths==null?new String[0]:splitPaths.clone();
        boolean[] allows=splitAllowNoDex==null?new boolean[0]:splitAllowNoDex.clone();
        ArrayList<Entry> result=new ArrayList<>();result.add(new Entry("base",basePath,null,baseAllowNoDex));HashSet<String> slots=new HashSet<>(),seenPaths=new HashSet<>();seenPaths.add(basePath);
        for(int i=0;i<names.length;i++){
            String name=names[i],rawPath=paths[i];if(!printable(name)||name.length()>122||!path(rawPath))throw new IllegalArgumentException("invalid split identity");
            String slot="split."+name;if(!slots.add(slot)||!seenPaths.add(rawPath))throw new IllegalArgumentException("duplicate split identity or path");
            result.add(new Entry(slot,rawPath,name,allows[i]));
        }
        return new ApkMetadataPlan(packageName,declaration,result);
    }
}
