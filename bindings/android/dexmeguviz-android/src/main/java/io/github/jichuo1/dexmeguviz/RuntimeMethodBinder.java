package io.github.jichuo1.dexmeguviz;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/** Explicit, uncached method-definition binding. Loading can execute caller ClassLoader code. */
public final class RuntimeMethodBinder {
    private RuntimeMethodBinder() {}

    public enum Status { BOUND, INVALID_INPUT, UNSUPPORTED_MEMBER, OWNER_NOT_FOUND,
        SIGNATURE_TYPE_NOT_FOUND, SIGNATURE_MISMATCH, INVOCATION_MISMATCH, AMBIGUOUS, LOADER_ERROR, REFLECTION_ERROR }
    public enum InvocationKind { STATIC, INSTANCE, UNKNOWN }
    /** A matching runtime declaration does not authenticate the scanned source. */
    public enum Origin { UNVERIFIED }

    /** Field references are fixed; referenced Method, loader and token may be mutable. The token is caller-owned, process-local and compared by identity. */
    public static final class Result {
        public final Status status;
        public final Origin origin;
        public final InvocationKind expectedInvocationKind, actualInvocationKind;
        public final String declaredOwner, name, prototype;
        public final ClassLoader initiatingLoader, definingLoader;
        /** False means definingLoader could not be observed; true/null means bootstrap. */
        public final boolean definingLoaderKnown;
        public final Object loaderGeneration;
        public final Class<?> declaringClass;
        public final Method method;
        public final int sourceIndex, inputIndex;
        public final String sourceSlot, occurrenceId;
        private Result(Status status, ClassLoader initiatingLoader, Object generation, String owner,
                String name, String prototype, Class<?> declaringClass, Method method,
                int sourceIndex, int inputIndex, String sourceSlot, String occurrenceId, InvocationKind expected, InvocationKind actual,
                ClassLoader definingLoader, boolean definingLoaderKnown) {
            this.status=status; this.origin=Origin.UNVERIFIED; this.expectedInvocationKind=expected; this.actualInvocationKind=actual; this.initiatingLoader=initiatingLoader;
            this.loaderGeneration=generation; this.declaredOwner=owner; this.name=name; this.prototype=prototype;
            this.declaringClass=declaringClass; this.definingLoader=definingLoader; this.definingLoaderKnown=definingLoaderKnown;
            this.method=method; this.sourceIndex=sourceIndex; this.inputIndex=inputIndex;
            this.sourceSlot=sourceSlot; this.occurrenceId=occurrenceId;
        }
        /** This only compares the supplied identity token; it cannot detect loader mutation. */
        public boolean isForGeneration(Object current) { return loaderGeneration!=null && loaderGeneration==current; }
    }

    /** Binds a copied method-definition candidate. No query completeness or origin is inferred. */
    public static Result bind(ClassLoader initiatingLoader, Object loaderGeneration, NativeEngine.MethodCandidate candidate) {
        if(candidate==null)return result(Status.INVALID_INPUT,initiatingLoader,loaderGeneration,null,null,null,null,null,-1,-1,null,null,InvocationKind.UNKNOWN);
        return bind0(initiatingLoader,loaderGeneration,candidate.owner,candidate.name,candidate.prototype,
                candidate.sourceIndex,candidate.inputIndex,candidate.sourceSlot,candidate.occurrenceId,
                (candidate.accessFlags & 8L)!=0?InvocationKind.STATIC:InvocationKind.INSTANCE);
    }

    /** Binds a declared method descriptor; this form has no static source occurrence. */
    public static Result bindDescriptor(ClassLoader initiatingLoader, Object loaderGeneration,
            String owner, String name, String prototype) {
        return bind0(initiatingLoader,loaderGeneration,owner,name,prototype,-1,-1,null,null,InvocationKind.UNKNOWN);
    }

    private static Result result(Status s, ClassLoader l, Object generation,String owner,String name,String proto,
            Class<?> ownerClass,Method method,int source,int input,String slot,String occurrence,InvocationKind expected) {
        InvocationKind actual=method==null?InvocationKind.UNKNOWN:
                (java.lang.reflect.Modifier.isStatic(method.getModifiers())?InvocationKind.STATIC:InvocationKind.INSTANCE);
        ClassLoader defining=null;boolean definingKnown=false;
        if(ownerClass!=null) {
            try { defining=ownerClass.getClassLoader();definingKnown=true; }
            catch(RuntimeException|LinkageError e) { s=Status.REFLECTION_ERROR; }
        }
        return new Result(s,l,generation,owner,name,proto,ownerClass,s==Status.BOUND?method:null,source,input,slot,occurrence,expected,actual,defining,definingKnown);
    }
    static boolean validOwner(String value) {
        if(value==null||value.length()<3||value.length()>65535||value.charAt(0)!='L'||value.charAt(value.length()-1)!=';')return false;
        String body=value.substring(1,value.length()-1);
        if(body.startsWith("/")||body.endsWith("/")||body.contains("//"))return false;
        for(int i=0;i<body.length();i++){char c=body.charAt(i);if(c=='.'||c==';'||c=='['||c==0)return false;}
        return true;
    }
    static final class Signature {
        final List<String> parameters; final String result;
        Signature(List<String> p,String r){parameters=p;result=r;}
    }
    static int typeEnd(String s,int at,boolean allowVoid) {
        if(at>=s.length())throw new IllegalArgumentException();
        int start=at,depth=0;while(at<s.length()&&s.charAt(at)=='['){if(++depth>255)throw new IllegalArgumentException();at++;}
        if(at>=s.length())throw new IllegalArgumentException();char kind=s.charAt(at++);
        if(kind=='L'){
            int end=s.indexOf(';',at);if(end<0||!validOwner(s.substring(at-1,end+1)))throw new IllegalArgumentException();at=end+1;
        } else if("ZBSCIJFD".indexOf(kind)<0 && !(kind=='V'&&allowVoid&&depth==0))throw new IllegalArgumentException();
        if(at==start)throw new IllegalArgumentException();return at;
    }
    static Signature parse(String proto) {
        if(proto==null||proto.length()<3||proto.length()>65535||proto.charAt(0)!='(')throw new IllegalArgumentException();
        int at=1;List<String> params=new ArrayList<>();
        while(at<proto.length()&&proto.charAt(at)!=')'){
            if(params.size()==255)throw new IllegalArgumentException();int next=typeEnd(proto,at,false);params.add(proto.substring(at,next));at=next;
        }
        if(at>=proto.length()||proto.charAt(at)!=')')throw new IllegalArgumentException();
        int from=at+1,end=typeEnd(proto,from,true);if(end!=proto.length())throw new IllegalArgumentException();
        return new Signature(params,proto.substring(from,end));
    }
    static Class<?> type(String desc,ClassLoader loader) throws ClassNotFoundException {
        switch(desc){case "V":return void.class;case "Z":return boolean.class;case "B":return byte.class;
            case "S":return short.class;case "C":return char.class;case "I":return int.class;
            case "J":return long.class;case "F":return float.class;case "D":return double.class;default:break;}
        String name=desc.charAt(0)=='['?desc.replace('/','.') : desc.substring(1,desc.length()-1).replace('/','.');
        Class<?> value=Class.forName(name,false,loader); if(!value.getName().equals(name))throw new IllegalStateException("loader returned wrong type"); return value;
    }
    private static Result bind0(ClassLoader loader,Object generation,String owner,String name,String proto,
            int source,int input,String slot,String occurrence,InvocationKind expected) {
        if(generation==null||!validOwner(owner)||name==null||name.isEmpty()||name.length()>65535||
                name.indexOf('/')>=0||name.indexOf('.')>=0||name.indexOf(';')>=0||name.indexOf('[')>=0||name.indexOf('\0')>=0)
            return result(Status.INVALID_INPUT,loader,generation,owner,name,proto,null,null,source,input,slot,occurrence,expected);
        if(name.charAt(0)=='<')return result(Status.UNSUPPORTED_MEMBER,loader,generation,owner,name,proto,null,null,source,input,slot,occurrence,expected);
        final Signature sig;
        try {sig=parse(proto);} catch(IllegalArgumentException e){return result(Status.INVALID_INPUT,loader,generation,owner,name,proto,null,null,source,input,slot,occurrence,expected);}
        final Class<?> ownerClass;
        try {String binary=owner.substring(1,owner.length()-1).replace('/','.'); ownerClass=Class.forName(binary,false,loader); if(!ownerClass.getName().equals(binary))throw new IllegalStateException("loader returned wrong owner");}
        catch(ClassNotFoundException e){return result(Status.OWNER_NOT_FOUND,loader,generation,owner,name,proto,null,null,source,input,slot,occurrence,expected);}
        catch(LinkageError|SecurityException e){return result(Status.LOADER_ERROR,loader,generation,owner,name,proto,null,null,source,input,slot,occurrence,expected);}
        catch(RuntimeException e){return result(Status.LOADER_ERROR,loader,generation,owner,name,proto,null,null,source,input,slot,occurrence,expected);}
        try {
            Class<?>[] params=new Class<?>[sig.parameters.size()];
            for(int i=0;i<params.length;i++)params[i]=type(sig.parameters.get(i),loader);
            Class<?> ret=type(sig.result,loader);Method match=null;
            for(Method m:ownerClass.getDeclaredMethods()){
                if(!m.getName().equals(name)||m.getReturnType()!=ret)continue;
                Class<?>[] actual=m.getParameterTypes();if(actual.length!=params.length)continue;
                boolean same=true;for(int i=0;i<actual.length;i++)if(actual[i]!=params[i]){same=false;break;}
                if(!same)continue;if(match!=null)return result(Status.AMBIGUOUS,loader,generation,owner,name,proto,ownerClass,null,source,input,slot,occurrence,expected);
                match=m;
            }
            InvocationKind actual=match==null?InvocationKind.UNKNOWN:
                (java.lang.reflect.Modifier.isStatic(match.getModifiers())?InvocationKind.STATIC:InvocationKind.INSTANCE);
            Status status=match==null?Status.SIGNATURE_MISMATCH:
                expected!=InvocationKind.UNKNOWN && expected!=actual?Status.INVOCATION_MISMATCH:Status.BOUND;
            return result(status,loader,generation,owner,name,proto,ownerClass,match,source,input,slot,occurrence,expected);
        } catch(ClassNotFoundException e){return result(Status.SIGNATURE_TYPE_NOT_FOUND,loader,generation,owner,name,proto,ownerClass,null,source,input,slot,occurrence,expected);}
          catch(SecurityException|LinkageError e){return result(Status.REFLECTION_ERROR,loader,generation,owner,name,proto,ownerClass,null,source,input,slot,occurrence,expected);}
          catch(RuntimeException e){return result(Status.REFLECTION_ERROR,loader,generation,owner,name,proto,ownerClass,null,source,input,slot,occurrence,expected);}
    }
}
