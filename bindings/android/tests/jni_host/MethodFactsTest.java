package io.github.jichuo1.dexmeguviz;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class MethodFactsTest {
 static void check(boolean ok,String msg){if(!ok)throw new AssertionError(msg);}
 static void status(int expected,Runnable action){try{action.run();throw new AssertionError("expected status "+expected);}catch(NativeEngine.NativeFailure e){check(e.status==expected,"status "+e.status);}}
 static void invalid(Runnable action){try{action.run();throw new AssertionError("invalid options accepted");}catch(IllegalArgumentException expected){}}
 public static void main(String[] args)throws Exception{
  check(args.length==6,"fixture args");byte[] basic=Files.readAllBytes(Path.of(args[0]));MethodFactsResult saved;
  try(var snapshot=NativeEngine.openRawDex(basic,"single")){
   saved=snapshot.inspectMethodFacts(3,63,128,1000000,10000);
   check(saved.methodRef==3&&saved.sourceIndex==0&&saved.hasBody&&saved.instructionChecked,"method identity");
   for(var category:MethodFactsResult.Category.values())check(saved.availability(category)==MethodFactsResult.Availability.CHECKED,"requested availability");
   check(saved.stringCount()==1&&saved.fieldCount()==1&&saved.numberCount()==0&&saved.invokeCount()==1&&saved.typeCount()==0&&saved.instructionCount()==4,"fact counts");
   check(saved.string(0).dexPc==0&&saved.string(0).stringIndex==10&&saved.string(0).value.equals("used-string"),"string fact");
   check(saved.field(0).dexPc==5&&saved.field(0).fieldIndex==0&&saved.field(0).owner!=null&&saved.field(0).name!=null&&saved.field(0).typeDescriptor.equals("I"),"field identity");
   check(saved.invoke(0).dexPc==2&&saved.invoke(0).targetDomain==2&&saved.invoke(0).targetIndex==4&&saved.invoke(0).name.equals("sink"),"invoke");
   check(saved.instruction(0).dexPc==0&&saved.instruction(0).opcode==0x1a&&saved.instruction(0).width==2,"instruction");
   var none=snapshot.inspectMethodFacts(0,63,128,1000000,0);check(!none.hasBody&&!none.instructionChecked&&none.availability(MethodFactsResult.Category.STRINGS)==MethodFactsResult.Availability.NO_BODY&&none.stringCount()==0,"no body");
   var only=snapshot.inspectMethodFacts(3,1,128,1000000,0);check(only.availability(MethodFactsResult.Category.FIELDS)==MethodFactsResult.Availability.NOT_REQUESTED,"not requested");
   try{only.fieldCount();throw new AssertionError("unrequested treated as empty");}catch(UnsupportedOperationException expected){}
   status(3,()->snapshot.inspectMethodFacts(4,1,128,1000000,0));status(4,()->snapshot.inspectMethodFacts(3,63,1,1000000,0));
   invalid(()->snapshot.inspectMethodFacts(3,0,128,1000000,0));invalid(()->snapshot.inspectMethodFacts(3,64,128,1000000,0));
  }
  check(saved.string(0).value.equals("used-string")&&saved.callerName.equals("uses"),"copied facts after close");
  try(var snapshot=NativeEngine.openRawDexSet(new byte[][]{basic,basic},new String[]{"one","two"})){
   var a=snapshot.inspectMethodFacts(0,3,1,128,1000000,0);var b=snapshot.inspectMethodFacts(1,3,1,128,1000000,0);check(a.sourceIndex==0&&b.sourceIndex==1&&!a.occurrenceId.equals(b.occurrenceId)&&a.contentId.equals(b.contentId),"source occurrence");}
  byte[] numeric=Files.readAllBytes(Path.of(args[1]));try(var snapshot=NativeEngine.openRawDex(numeric,"numeric")){var f=snapshot.inspectMethodFacts(3,4,128,1000000,0);check(f.numberCount()==3&&f.number(0).bits==0xffffffffL&&f.number(0).widthBits==32&&f.number(1).bits==-2L&&f.number(1).widthBits==64&&f.number(2).bits==0x80000000L,"numeric bit pattern");}
  byte[] type=Files.readAllBytes(Path.of(args[2]));try(var snapshot=NativeEngine.openRawDex(type,"types")){var f=snapshot.inspectMethodFacts(3,16,128,1000000,0);check(f.typeCount()==1&&f.type(0).typeIndex==5&&f.type(0).dexPc==0&&f.type(0).opcode==0x22&&f.type(0).descriptor.equals("Lfixture/TypeUses$Parent;"),"type fact");}
  byte[] unicode=Files.readAllBytes(Path.of(args[3]));try(var snapshot=NativeEngine.openRawDex(unicode,"utf")){var f=snapshot.inspectMethodFacts(3,1,128,1000000,0);String expected=new String(new char[]{'u','s','e','d',0,(char)0xd800,'x','y'});check(f.stringCount()==2&&f.string(0).value.equals(expected)&&f.string(1).value.equals(expected),"UTF16 NUL and unpaired surrogate");}
  byte[] unusual=Files.readAllBytes(Path.of(args[4]));try(var snapshot=NativeEngine.openRawDex(unusual,"domains")){var f=snapshot.inspectMethodFacts(3,8,128,1000000,0);check(f.invokeCount()==2&&f.invoke(0).targetDomain==3&&f.invoke(0).extraPrototype!=null&&f.invoke(1).targetDomain==4&&f.invoke(1).owner==null,"invoke domains");}
  byte[] names=Files.readAllBytes(Path.of(args[5]));try(var snapshot=NativeEngine.openRawDex(names,"names")){var f=snapshot.inspectMethodFacts(0,1,128,1000000,0);check(f.callerName.equals("method\ud83d\ude00")&&f.availability(MethodFactsResult.Category.STRINGS)==MethodFactsResult.Availability.NO_BODY,"caller supplementary UTF16");}
  try{MethodFactsResult.decode(new byte[]{0,0,0,0});throw new AssertionError("bad wire accepted");}catch(IllegalStateException expected){}
  System.out.println("PASS generic selected method facts, categories, source, raw bits, UTF16, invoke domains and lifetime");
 }
}
