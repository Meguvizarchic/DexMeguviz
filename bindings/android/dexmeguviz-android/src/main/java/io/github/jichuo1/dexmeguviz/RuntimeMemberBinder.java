package io.github.jichuo1.dexmeguviz;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/** Explicit uncached declared-member/owner binding; a caller's ClassLoader can execute code. */
public final class RuntimeMemberBinder {
    private RuntimeMemberBinder() {}

    public enum Kind { CONSTRUCTOR, FIELD, OWNER }
    public enum Status { BOUND, OWNER_ONLY, INVALID_INPUT, UNSUPPORTED_RELATION, OWNER_NOT_FOUND,
        SIGNATURE_TYPE_NOT_FOUND, SIGNATURE_MISMATCH, INVOCATION_MISMATCH, AMBIGUOUS, LOADER_ERROR, REFLECTION_ERROR }

    /** Field references are fixed; referenced Class, member, loader and token may be mutable. */
    public static final class Result {
        public final Kind kind;
        public final Status status;
        public final RuntimeMethodBinder.Origin origin;
        public final RuntimeMethodBinder.InvocationKind expectedInvocationKind, actualInvocationKind;
        public final String declaredOwner, name, descriptor;
        public final ClassLoader initiatingLoader, definingLoader;
        public final boolean definingLoaderKnown, memberVerified;
        public final Object loaderGeneration;
        public final Class<?> declaringClass;
        public final Constructor<?> constructor;
        public final Field field;
        public final int sourceIndex, inputIndex;
        public final String sourceSlot, occurrenceId;
        private Result(Kind kind, Status status, ClassLoader loader, Object generation, String owner,
                String name, String descriptor, Class<?> declaringClass, ClassLoader definingLoader,
                boolean definingLoaderKnown, Constructor<?> constructor, Field field,
                RuntimeMethodBinder.InvocationKind expected, RuntimeMethodBinder.InvocationKind actual,
                int sourceIndex, int inputIndex, String sourceSlot, String occurrenceId) {
            this.kind=kind;this.status=status;this.origin=RuntimeMethodBinder.Origin.UNVERIFIED;
            this.initiatingLoader=loader;this.definingLoader=definingLoader;this.definingLoaderKnown=definingLoaderKnown;
            this.loaderGeneration=generation;this.declaredOwner=owner;this.name=name;this.descriptor=descriptor;
            this.declaringClass=declaringClass;this.memberVerified=status==Status.BOUND;
            this.constructor=status==Status.BOUND?constructor:null;this.field=status==Status.BOUND?field:null;
            this.expectedInvocationKind=expected;this.actualInvocationKind=actual;
            this.sourceIndex=sourceIndex;this.inputIndex=inputIndex;this.sourceSlot=sourceSlot;this.occurrenceId=occurrenceId;
        }
        /** Token identity only; no mutation, lifetime or origin proof is implied. */
        public boolean isForGeneration(Object current){return loaderGeneration!=null && loaderGeneration==current;}
    }
    private static final class Context {
        final Kind kind;final ClassLoader loader;final Object generation;final String owner,name,descriptor;
        final int source,input;final String slot,occurrence;final RuntimeMethodBinder.InvocationKind expected;
        Context(Kind kind,ClassLoader loader,Object generation,String owner,String name,String descriptor,
                int source,int input,String slot,String occurrence,RuntimeMethodBinder.InvocationKind expected){
            this.kind=kind;this.loader=loader;this.generation=generation;this.owner=owner;this.name=name;this.descriptor=descriptor;
            this.source=source;this.input=input;this.slot=slot;this.occurrence=occurrence;this.expected=expected;
        }
        Result finish(Status status,Class<?> ownerClass,Constructor<?> constructor,Field field,
                RuntimeMethodBinder.InvocationKind actual){
            ClassLoader defining=null;boolean known=false;
            if(ownerClass!=null){try{defining=ownerClass.getClassLoader();known=true;}catch(RuntimeException|LinkageError e){status=Status.REFLECTION_ERROR;}}
            return new Result(kind,status,loader,generation,owner,name,descriptor,ownerClass,defining,known,constructor,field,
                    expected,actual,source,input,slot,occurrence);
        }
    }
    private static RuntimeMethodBinder.InvocationKind kind(Long flags){
        return flags==null?RuntimeMethodBinder.InvocationKind.UNKNOWN:(flags&8L)!=0?
                RuntimeMethodBinder.InvocationKind.STATIC:RuntimeMethodBinder.InvocationKind.INSTANCE;
    }
    private static boolean memberName(String name){
        return name!=null&&!name.isEmpty()&&name.length()<=65535&&name.indexOf('/')<0&&name.indexOf('.')<0&&
                name.indexOf(';')<0&&name.indexOf('[')<0&&name.indexOf('\0')<0&&name.charAt(0)!='<';
    }
    private static Class<?> owner(Context c)throws ClassNotFoundException {
        String binary=c.owner.substring(1,c.owner.length()-1).replace('/','.');Class<?> value=Class.forName(binary,false,c.loader);
        if(!value.getName().equals(binary))throw new IllegalStateException("loader returned wrong owner");return value;
    }
    private static Result invalid(Context c,Status status){return c.finish(status,null,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN);}
    private static boolean valid(Context c){return c.generation!=null && RuntimeMethodBinder.validOwner(c.owner);}

    /** Bind a field_defs row; references are not silently treated as definitions. */
    public static Result bindField(ClassLoader loader,Object generation,NativeEngine.EntityCandidate candidate){
        if(candidate==null)return bindField0(new Context(Kind.FIELD,loader,generation,null,null,null,-1,-1,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN),Status.INVALID_INPUT);
        Context c=new Context(Kind.FIELD,loader,generation,candidate.owner,candidate.name,candidate.typeDescriptor,
                candidate.sourceIndex,candidate.inputIndex,candidate.sourceSlot,candidate.occurrenceId,kind(candidate.accessFlags));
        return bindField0(c,candidate.relation==2?null:Status.UNSUPPORTED_RELATION);
    }
    /** Null expectedStatic means no static-vs-instance expectation was supplied. */
    public static Result bindFieldDescriptor(ClassLoader loader,Object generation,String owner,String name,String type,Boolean expectedStatic){
        RuntimeMethodBinder.InvocationKind expected=expectedStatic==null?RuntimeMethodBinder.InvocationKind.UNKNOWN:
                expectedStatic?RuntimeMethodBinder.InvocationKind.STATIC:RuntimeMethodBinder.InvocationKind.INSTANCE;
        return bindField0(new Context(Kind.FIELD,loader,generation,owner,name,type,-1,-1,null,null,expected),null);
    }
    private static Result bindField0(Context c,Status precondition){
        if(precondition!=null)return invalid(c,precondition);
        if(!valid(c)||!memberName(c.name)||c.descriptor==null||c.descriptor.length()>65535)return invalid(c,Status.INVALID_INPUT);
        try { if(RuntimeMethodBinder.typeEnd(c.descriptor,0,false)!=c.descriptor.length())return invalid(c,Status.INVALID_INPUT); }
        catch(IllegalArgumentException e){return invalid(c,Status.INVALID_INPUT);}
        final Class<?> typeOwner;
        try{typeOwner=owner(c);}catch(ClassNotFoundException e){return invalid(c,Status.OWNER_NOT_FOUND);}
        catch(RuntimeException|LinkageError e){return invalid(c,Status.LOADER_ERROR);}
        try{
            Class<?> requested=RuntimeMethodBinder.type(c.descriptor,c.loader);Field match=null;
            for(Field f:typeOwner.getDeclaredFields()){
                if(!f.getName().equals(c.name)||f.getType()!=requested)continue;
                if(match!=null)return c.finish(Status.AMBIGUOUS,typeOwner,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN);
                match=f;
            }
            RuntimeMethodBinder.InvocationKind actual=match==null?RuntimeMethodBinder.InvocationKind.UNKNOWN:
                    Modifier.isStatic(match.getModifiers())?RuntimeMethodBinder.InvocationKind.STATIC:RuntimeMethodBinder.InvocationKind.INSTANCE;
            Status status=match==null?Status.SIGNATURE_MISMATCH:c.expected!=RuntimeMethodBinder.InvocationKind.UNKNOWN&&c.expected!=actual?
                    Status.INVOCATION_MISMATCH:Status.BOUND;
            return c.finish(status,typeOwner,null,match,actual);
        }catch(ClassNotFoundException e){return c.finish(Status.SIGNATURE_TYPE_NOT_FOUND,typeOwner,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN);}
         catch(RuntimeException|LinkageError e){return c.finish(Status.REFLECTION_ERROR,typeOwner,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN);}
    }

    /** Bind an actual method_defs constructor, not an initializer or external reference. */
    public static Result bindConstructor(ClassLoader loader,Object generation,NativeEngine.MethodCandidate candidate){
        if(candidate==null)return bindConstructor0(new Context(Kind.CONSTRUCTOR,loader,generation,null,null,null,-1,-1,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN),Status.INVALID_INPUT);
        Context c=new Context(Kind.CONSTRUCTOR,loader,generation,candidate.owner,candidate.name,candidate.prototype,
                candidate.sourceIndex,candidate.inputIndex,candidate.sourceSlot,candidate.occurrenceId,kind(candidate.accessFlags));
        return bindConstructor0(c,null);
    }
    /** Descriptor-only input has no static DEX expectation. */
    public static Result bindConstructorDescriptor(ClassLoader loader,Object generation,String owner,String prototype){
        return bindConstructor0(new Context(Kind.CONSTRUCTOR,loader,generation,owner,"<init>",prototype,-1,-1,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN),null);
    }
    private static Result bindConstructor0(Context c,Status precondition){
        if(precondition!=null)return invalid(c,precondition);
        if(!valid(c)||!"<init>".equals(c.name))return invalid(c,Status.INVALID_INPUT);
        final RuntimeMethodBinder.Signature sig;
        try {sig=RuntimeMethodBinder.parse(c.descriptor);if(!"V".equals(sig.result))return invalid(c,Status.INVALID_INPUT);}
        catch(IllegalArgumentException e){return invalid(c,Status.INVALID_INPUT);}
        final Class<?> typeOwner;
        try{typeOwner=owner(c);}catch(ClassNotFoundException e){return invalid(c,Status.OWNER_NOT_FOUND);}
        catch(RuntimeException|LinkageError e){return invalid(c,Status.LOADER_ERROR);}
        try{
            Class<?>[] params=new Class<?>[sig.parameters.size()];for(int i=0;i<params.length;i++)params[i]=RuntimeMethodBinder.type(sig.parameters.get(i),c.loader);
            Constructor<?> match=null;
            for(Constructor<?> ctor:typeOwner.getDeclaredConstructors()){
                Class<?>[] actual=ctor.getParameterTypes();if(actual.length!=params.length)continue;
                boolean same=true;for(int i=0;i<actual.length;i++)if(actual[i]!=params[i]){same=false;break;}
                if(!same)continue;if(match!=null)return c.finish(Status.AMBIGUOUS,typeOwner,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN);match=ctor;
            }
            RuntimeMethodBinder.InvocationKind actual=match==null?RuntimeMethodBinder.InvocationKind.UNKNOWN:RuntimeMethodBinder.InvocationKind.INSTANCE;
            Status status=match==null?Status.SIGNATURE_MISMATCH:c.expected==RuntimeMethodBinder.InvocationKind.STATIC?Status.INVOCATION_MISMATCH:Status.BOUND;
            return c.finish(status,typeOwner,match,null,actual);
        }catch(ClassNotFoundException e){return c.finish(Status.SIGNATURE_TYPE_NOT_FOUND,typeOwner,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN);}
         catch(RuntimeException|LinkageError e){return c.finish(Status.REFLECTION_ERROR,typeOwner,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN);}
    }

    /** Bind only the owner of a class_defs row; no member is verified. */
    public static Result bindClass(ClassLoader loader,Object generation,NativeEngine.EntityCandidate candidate){
        if(candidate==null)return invalid(new Context(Kind.OWNER,loader,generation,null,null,null,-1,-1,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN),Status.INVALID_INPUT);
        Context c=new Context(Kind.OWNER,loader,generation,candidate.typeDescriptor,null,null,candidate.sourceIndex,candidate.inputIndex,
                candidate.sourceSlot,candidate.occurrenceId,RuntimeMethodBinder.InvocationKind.UNKNOWN);
        return bindOwner0(c,candidate.relation==1?null:Status.UNSUPPORTED_RELATION);
    }
    /** Bind only an owner; the descriptor has no source occurrence. */
    public static Result bindOwnerDescriptor(ClassLoader loader,Object generation,String owner){
        return bindOwner0(new Context(Kind.OWNER,loader,generation,owner,null,null,-1,-1,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN),null);
    }
    /** A static init/constructor row is only a class anchor, never a runtime member verification. */
    public static Result bindOwnerAnchor(ClassLoader loader,Object generation,NativeEngine.MethodCandidate candidate){
        if(candidate==null)return invalid(new Context(Kind.OWNER,loader,generation,null,null,null,-1,-1,null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN),Status.INVALID_INPUT);
        Context c=new Context(Kind.OWNER,loader,generation,candidate.owner,candidate.name,candidate.prototype,candidate.sourceIndex,candidate.inputIndex,
                candidate.sourceSlot,candidate.occurrenceId,kind(candidate.accessFlags));
        try{
            if("<clinit>".equals(c.name)){
                if(!"()V".equals(c.descriptor)||c.expected!=RuntimeMethodBinder.InvocationKind.STATIC)return invalid(c,Status.INVALID_INPUT);
            }else if("<init>".equals(c.name)){
                if(!"V".equals(RuntimeMethodBinder.parse(c.descriptor).result)||c.expected!=RuntimeMethodBinder.InvocationKind.INSTANCE)return invalid(c,Status.INVALID_INPUT);
            }else return invalid(c,Status.UNSUPPORTED_RELATION);
        }catch(IllegalArgumentException e){return invalid(c,Status.INVALID_INPUT);}
        return bindOwner0(c,null);
    }
    private static Result bindOwner0(Context c,Status precondition){
        if(precondition!=null)return invalid(c,precondition);if(!valid(c))return invalid(c,Status.INVALID_INPUT);
        try{return c.finish(Status.OWNER_ONLY,owner(c),null,null,RuntimeMethodBinder.InvocationKind.UNKNOWN);}
        catch(ClassNotFoundException e){return invalid(c,Status.OWNER_NOT_FOUND);}
        catch(RuntimeException|LinkageError e){return invalid(c,Status.LOADER_ERROR);}
    }
}
