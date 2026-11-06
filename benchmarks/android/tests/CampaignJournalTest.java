import io.github.jichuo1.dexmeguviz.bench.CampaignJournal;
import io.github.jichuo1.dexmeguviz.bench.TaskProbe;
import io.github.jichuo1.dexmeguviz.bench.ProbeRecordBridge;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class CampaignJournalTest {
    static void check(boolean v,String m){if(!v)throw new AssertionError(m);}
    static CampaignJournal open(Path file,String protocol,String identity,byte[] json)throws Exception {
        return new CampaignJournal(file,"unit-campaign","synthetic_control",protocol,identity,json,120L*1024*1024);
    }
    public static void main(String[] args)throws Exception {
        check(args.length==4,"arguments");Path dir=Paths.get(args[0]);String protocol=args[1],identity=args[2];byte[] json=Files.readAllBytes(Paths.get(args[3]));
        TaskProbe.Result<?> valid=ProbeRecordBridgeTest.fixture(false,28500);String projection=String.join("",java.util.Collections.nCopies(64,"a"));
        Map<String,Object> facts=ProbeRecordBridgeTest.facts(identity,"build",projection);
        Files.write(dir.resolve("expected-record.json"),ProbeRecordBridge.jsonRecord(valid,facts).getBytes(StandardCharsets.UTF_8),java.nio.file.StandardOpenOption.CREATE_NEW,java.nio.file.StandardOpenOption.WRITE);
        Path complete=dir.resolve("complete.jsonl");CampaignJournal journal=open(complete,protocol,identity,json);
        journal.append(valid,facts);journal.append(null,facts);journal.finish("{}".getBytes(StandardCharsets.UTF_8));
        boolean rejected=false;try{journal.append(valid,facts);}catch(IllegalStateException expected){rejected=true;}check(rejected,"post finish append");
        rejected=false;try{open(complete,protocol,identity,json);}catch(java.nio.file.FileAlreadyExistsException expected){rejected=true;}check(rejected,"no overwrite");
        try(CampaignJournal partial=open(dir.resolve("partial.jsonl"),protocol,identity,json)){partial.append(valid,facts);}
        CampaignJournal failed=open(dir.resolve("failed.jsonl"),protocol,identity,json);
        List<Object> cycle=new ArrayList<>();cycle.add(cycle);Map<String,Object> corrupt=new LinkedHashMap<>(facts);corrupt.put("counters",cycle);
        rejected=false;try{failed.append(valid,corrupt);}catch(IllegalArgumentException expected){rejected=true;}finally{failed.close();}check(rejected,"serialization failure");
        TaskProbe probe=new TaskProbe(System::nanoTime,()->120000L,64);
        TaskProbe.Result<String> observed=probe.measure(markers->{markers.prepared();markers.firstAnswer();Thread.sleep(35);markers.closing();return "fake-pss";});
        check(observed.taskInvoked&&observed.taskReturned,"real host probe invoked");
        try(CampaignJournal actual=open(dir.resolve("host-probe.jsonl"),protocol,identity,json)){actual.append(observed,facts);actual.finish("{}".getBytes(StandardCharsets.UTF_8));}
        String wrong=identity.equals(String.join("",java.util.Collections.nCopies(64,"a")))?String.join("",java.util.Collections.nCopies(64,"b")):String.join("",java.util.Collections.nCopies(64,"a"));
        try(CampaignJournal mismatch=open(dir.resolve("mismatch.jsonl"),protocol,wrong,json)){mismatch.append(valid,ProbeRecordBridgeTest.facts(wrong,"build",projection));mismatch.finish("{}".getBytes(StandardCharsets.UTF_8));}
        try(CampaignJournal malformed=open(dir.resolve("malformed-header.jsonl"),protocol,identity,"{]".getBytes(StandardCharsets.UTF_8))){malformed.finish("{}".getBytes(StandardCharsets.UTF_8));}
        CampaignJournal fatal=open(dir.resolve("fatal.jsonl"),protocol,identity,json);
        Map<String,Object> throwsError=new java.util.AbstractMap<String,Object>() {
            @Override public Object get(Object key){throw new AssertionError("synthetic");}
            @Override public java.util.Set<java.util.Map.Entry<String,Object>> entrySet(){return java.util.Collections.emptySet();}
        };
        rejected=false;try{fatal.append(valid,throwsError);}catch(AssertionError expected){rejected=true;}check(rejected,"fatal serialization");
        rejected=false;try{fatal.finish("{}".getBytes(StandardCharsets.UTF_8));}catch(IllegalStateException expected){rejected=true;}finally{fatal.close();}check(rejected,"fatal serialization cannot be hidden by footer");
        CampaignJournal budget=new CampaignJournal(dir.resolve("budget.jsonl"),"unit-campaign","synthetic_control",protocol,identity,json,4096);
        rejected=false;try{budget.append(valid,facts);}catch(java.io.IOException expected){rejected=true;}check(rejected,"byte limit");
        rejected=false;try{budget.finish("{}".getBytes(StandardCharsets.UTF_8));}catch(IllegalStateException expected){rejected=true;}finally{budget.close();}check(rejected,"budget failure cannot be hidden by footer");
        System.out.println("PASS new-only append, complete, partial, serialization and byte-limit journals");
    }
}
