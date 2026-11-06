import io.github.jichuo1.dexmeguviz.FastDexQuery;
import io.github.jichuo1.dexmeguviz.NativeEngine;
import io.github.jichuo1.dexmeguviz.MethodCallsResult;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.ZipFile;
public class FastBridgeHostTest {
 static void check(boolean x,String what){if(!x)throw new AssertionError(what);}
 public static void main(String[] args)throws Exception{
  if(args[0].endsWith(".apk")){try(var zip=new ZipFile(args[0])){for(int i=1;i<=33;i++){String name=i==1?"classes.dex":"classes"+i+".dex";var entry=zip.getEntry(name);check(entry!=null,"missing "+name);System.out.print(name+" ");try(var stream=zip.getInputStream(entry)){run(args,stream.readAllBytes());}}}return;}run(args,Files.readAllBytes(Path.of(args[0])));
 }
 static void run(String[] args,byte[] dex)throws Exception{
  byte[][] qs=new byte[10][];boolean[] calls=new boolean[10];calls[7]=true;
  for(int i=0;i<9;i++)qs[i]=Files.readAllBytes(Path.of(args[1],"query-"+i+".json"));
  qs[9]="{\"schema_version\":1,\"relation\":\"class_defs\",\"where\":{\"descriptor\":{\"op\":\"prefix\",\"value\":\"Lcom/bilibili/playerbizcommonv2/widget/speed/\"}},\"intent\":\"enumerate\",\"max_results\":4096,\"max_work\":100000000}".getBytes(StandardCharsets.UTF_8);
  FastDexQuery.Result held;
  try(var plans=FastDexQuery.compile(qs,calls);var strict=NativeEngine.openRawDex(dex,"source")){
   var limits=new FastDexQuery.Limits(32L<<20,4096,10000,1<<20,1048576,1048576,8<<20);
   held=plans.scan(dex,FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX,limits);check(held.rules.size()==10,"rule count");int total=0;
   for(int i=0;i<9;i++){
    NativeEngine.QueryResult strictRow=null;NativeEngine.EntityResult reflect=null;
    if(i==2||i==7||i==8)reflect=strict.queryReflectionMethodUses(qs[i]);else strictRow=strict.queryMethods(qs[i]);
    var fast=held.rules.get(i);check(fast.coverage()==1&&fast.executionStatus==0&&!fast.resultLimit&&fast.unknownRows==0&&fast.callerAssertedExhaustive,"fast status "+i);
    long count=strictRow!=null?strictRow.candidateCount():reflect.candidateCount();String id=strictRow!=null?strictRow.queryId:reflect.queryId;
    check(fast.methods.size()==count&&fast.queryId.equals(id),"rule count or id "+i);
    for(int j=0;j<count;j++){
      var row=fast.methods.get(j);long ref,flags,decl,code;String owner,name,proto;
      if(strictRow!=null){var v=strictRow.candidate(j);ref=v.methodIndex;flags=v.accessFlags;decl=v.declarationOffset;code=v.codeOffset;owner=v.owner;name=v.name;proto=v.prototype;}
      else{var v=reflect.candidate(j);ref=v.referenceIndex;flags=v.accessFlags;decl=v.definitionOffset==null?-1:v.definitionOffset;code=v.codeOffset==null?0:v.codeOffset;owner=v.owner;name=v.name;proto=v.prototype;}
      check(row.methodRef==ref&&row.accessFlags==flags&&row.declarationOffset==decl&&row.codeOffset==code&&row.owner.equals(owner)&&row.name.equals(name)&&row.prototype.equals(proto),"candidate "+i+"/"+j);
      if(i==7){MethodCallsResult original=strict.inspectMethodCalls(row.methodRef,129,100000000L,0L);check(row.calls.size()==original.rowCount(),"call count");
       for(int k=0;k<row.calls.size();k++){var f=row.calls.get(k);var s=original.row(k);long kind=s.targetDomain==2?0:s.targetDomain==4?1:2;
        check(f.pc==s.dexPc&&f.opcode==s.opcode&&f.targetRef==s.targetIndex&&f.extraProto==s.extraProto&&f.referenceKind==kind&&Objects.equals(f.owner,s.owner)&&Objects.equals(f.name,s.name)&&Objects.equals(f.prototype,s.prototype)&&Objects.equals(f.extraPrototype,s.extraPrototype),"call "+k);}}
      total++;
    }
   }
   var classFast=held.rules.get(9);var classStrict=strict.queryEntities(qs[9]);check(classFast.relation==1&&classFast.executionStatus==0&&!classFast.resultLimit&&classFast.unknownRows==0&&classFast.callerAssertedExhaustive,"class status");check(classFast.classes.size()==classStrict.candidateCount()&&classFast.queryId.equals(classStrict.queryId),"class count or id");for(int j=0;j<classStrict.candidateCount();j++){var f=classFast.classes.get(j);var s=classStrict.candidate(j);check(f.localIndex==s.localIndex&&f.typeIndex==s.referenceIndex&&f.definitionOffset==s.definitionOffset&&f.accessFlags==s.accessFlags&&f.descriptor.equals(s.typeDescriptor),"class candidate "+j);}
   try{plans.scan(dex,FastDexQuery.InputAssumption.CALLER_ASSERTS_VALID_SORTED_DEX,new FastDexQuery.Limits(32L<<20,1,10000,1<<20,1048576,1048576,8<<20));if(total+classStrict.candidateCount()>1)throw new AssertionError("row budget");}
   catch(FastDexQuery.Failure expected){check(expected.status==4,"budget status "+expected.status);}
   System.out.println("PASS rules=9 candidates="+total+" all_calls=matched classes="+classFast.classes.size());
  }
  check(held.rules.size()==10,"result retained");
  try{FastDexQuery.compile(new byte[][]{"{\"schema_version\":1,\"relation\":\"field_defs\"}".getBytes(StandardCharsets.UTF_8)},new boolean[]{false});throw new AssertionError("unsupported accepted");}
  catch(FastDexQuery.Failure expected){check(expected.status==3&&expected.ruleIndex==0,"unsupported profile");}
 }
}
