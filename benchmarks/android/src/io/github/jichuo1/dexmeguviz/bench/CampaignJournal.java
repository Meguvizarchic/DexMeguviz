package io.github.jichuo1.dexmeguviz.bench;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

/** Append-only local capture journal. It does not authenticate host facts or perform any benchmark. */
public final class CampaignJournal implements Closeable {
    private static final long MAX_TOTAL=120L*1024*1024;
    private static final int MAX_PAYLOAD=32*1024*1024, MAX_IDENTITY=1024*1024, MAX_RECORDS=99998;
    private final FileChannel channel;
    private final long maxBytes;
    private final String protocolSha256,identitySha256,identityBytesSha256;
    private Object claim;
    private byte[] previous=new byte[32];
    private long sequence, written;
    private int records;
    private boolean closed,failed,finished;

    /** Creates a new file and durably writes a header. Identity JSON is checked during conversion. */
    public CampaignJournal(Path file,String campaignId,String dataKind,String protocolSha256,
                           String identitySha256,byte[] identityJson,long maxBytes) throws IOException {
        if(file==null||campaignId==null||dataKind==null||protocolSha256==null||identitySha256==null||identityJson==null)
            throw new NullPointerException("journal arguments");
        if(!campaignId.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")||
            !(dataKind.equals("real")||dataKind.equals("synthetic_control"))||
            !protocolSha256.matches("[0-9a-f]{64}")||!identitySha256.matches("[0-9a-f]{64}")||
            identityJson.length<2||identityJson.length>MAX_IDENTITY||maxBytes<4096||maxBytes>MAX_TOTAL)
            throw new IllegalArgumentException("invalid journal header or budget");
        // Freeze exactly the identity bytes written in the header. Preflight compares
        // their digest, but does not claim JSON canonicality or source authenticity.
        byte[] identityCopy=identityJson.clone();String identityBytesHash=hex(digest(identityCopy));
        Path path=file.toAbsolutePath().normalize();
        for(Path p=path.getParent();p!=null;p=p.getParent())if(Files.isSymbolicLink(p))throw new IOException("linked journal ancestor");
        channel=FileChannel.open(path,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS);
        this.maxBytes=maxBytes;this.protocolSha256=protocolSha256;this.identitySha256=identitySha256;this.identityBytesSha256=identityBytesHash;
        byte[] prefix=(dataKind+"\n"+campaignId+"\n"+protocolSha256+"\n"+identitySha256+"\n").getBytes(StandardCharsets.UTF_8);
        byte[] header=new byte[prefix.length+identityCopy.length];System.arraycopy(prefix,0,header,0,prefix.length);System.arraycopy(identityCopy,0,header,prefix.length,identityCopy.length);
        try{frame("header",header);}catch(IOException|RuntimeException|Error e){failed=true;try{channel.close();}catch(IOException close){e.addSuppressed(close);}closed=true;throw e;}
    }
    private static String hex(byte[] bytes){char[] out=new char[bytes.length*2];char[] digits="0123456789abcdef".toCharArray();for(int i=0;i<bytes.length;i++){out[2*i]=digits[(bytes[i]&255)>>>4];out[2*i+1]=digits[bytes[i]&15];}return new String(out);}
    private static byte[] digest(byte[] payload){
        try{return MessageDigest.getInstance("SHA-256").digest(payload);}catch(NoSuchAlgorithmException e){throw new AssertionError(e);}
    }
    private static byte[] hash(byte[] previous,long seq,String kind,byte[] payload){
        try{MessageDigest md=MessageDigest.getInstance("SHA-256");md.update(previous);md.update(ByteBuffer.allocate(8).putLong(seq).array());md.update(kind.getBytes(StandardCharsets.US_ASCII));md.update((byte)0);return md.digest(payload);}catch(NoSuchAlgorithmException e){throw new AssertionError(e);}
    }
    private void requireOpen(Object token){
        if(closed||failed||finished)throw new IllegalStateException("journal unavailable");
        if((claim==null&&token!=null)||(claim!=null&&claim!=token))throw new IllegalStateException("journal is exclusively claimed");
    }
    private void closeInternal()throws IOException{if(!closed){closed=true;channel.close();}}
    private void rejectFresh(String reason){
        failed=true;IllegalStateException failure=new IllegalStateException(reason);
        try{closeInternal();}catch(IOException | RuntimeException | Error close){if(close!=failure)failure.addSuppressed(close);}
        throw failure;
    }
    /** Atomic declared-header check and exclusive claim. Neither statement authenticates external inputs. */
    synchronized Object claimFresh(String expectedProtocol,String expectedIdentity)throws IOException{
        if(claim!=null)throw new IllegalStateException("journal already claimed");
        requireOpen(null);
        if(!protocolSha256.equals(expectedProtocol)||!identitySha256.equals(expectedIdentity)||
            !identitySha256.equals(identityBytesSha256))rejectFresh("journal binding mismatch");
        if(records!=0||sequence!=1)rejectFresh("journal is not fresh");
        final boolean intact;
        try{intact=channel.size()==written&&channel.position()==written;}
        catch(IOException | RuntimeException failure){failed=true;try{closeInternal();}catch(IOException | RuntimeException | Error close){if(close!=failure)failure.addSuppressed(close);}throw failure;}
        if(!intact)rejectFresh("journal changed externally");
        claim=new Object();return claim;
    }
    synchronized void releaseClaim(Object token)throws IOException{
        requireOpen(token);if(claim!=token||token==null)throw new IllegalStateException("invalid claim");
        if(channel.size()!=written||channel.position()!=written){failed=true;throw new IOException("journal changed externally");}
        claim=null;
    }
    synchronized void closeClaimed(Object token)throws IOException{
        if(claim!=token||token==null)throw new IllegalStateException("invalid claim");
        claim=null;closeInternal();
    }
    private void frame(String kind,byte[] payload)throws IOException {
        if(payload.length>MAX_PAYLOAD)throw new IllegalArgumentException("journal payload limit");
        byte[] digest=hash(previous,sequence,kind,payload);
        String encoded=Base64.getEncoder().encodeToString(payload);
        byte[] line=("{\"seq\":"+sequence+",\"kind\":\""+kind+"\",\"previous\":\""+hex(previous)+"\",\"payload_b64\":\""+encoded+"\",\"sha256\":\""+hex(digest)+"\"}\n").getBytes(StandardCharsets.US_ASCII);
        if(line.length>maxBytes-written){failed=true;throw new IOException("journal byte budget");}
        try{
            if(channel.size()!=written||channel.position()!=written)throw new IOException("journal changed externally");
            ByteBuffer buffer=ByteBuffer.wrap(line);while(buffer.hasRemaining()){if(channel.write(buffer)<=0)throw new IOException("journal write made no progress");}
            channel.force(true);written+=line.length;previous=digest;sequence++;
        }catch(IOException|RuntimeException e){failed=true;throw e;}
    }
    /** Appends a single measured record, including incomplete/failed records, without interpretation. */
    public synchronized void append(TaskProbe.Result<?> result,Map<String,?> facts)throws IOException {
        appendInternal(result,facts,null);
    }
    synchronized void appendClaimed(Object token,TaskProbe.Result<?> result,Map<String,?> facts)throws IOException {
        appendInternal(result,facts,token);
    }
    private void appendInternal(TaskProbe.Result<?> result,Map<String,?> facts,Object token)throws IOException {
        requireOpen(token);
        try{
            if(records>=MAX_RECORDS)throw new IOException("journal record limit");
            byte[] payload;
            try{payload=ProbeRecordBridge.jsonRecord(result,facts).getBytes(StandardCharsets.UTF_8);if(payload.length>MAX_PAYLOAD)throw new IllegalArgumentException("record limit");}
            catch(RuntimeException error){try{frame("error",error.getClass().getName().getBytes(StandardCharsets.UTF_8));}catch(IOException|RuntimeException writeFailure){error.addSuppressed(writeFailure);}throw error;}
            frame("record",payload);records++;
        }catch(IOException|RuntimeException|Error failure){failed=true;throw failure;}
    }
    /** Writes the caller-supplied external gate evidence object; conversion validates the JSON. */
    public synchronized void finish(byte[] externalGateEvidenceJson)throws IOException {
        requireOpen(null);if(externalGateEvidenceJson==null||externalGateEvidenceJson.length>MAX_IDENTITY)throw new IllegalArgumentException("gate JSON limit");
        try{frame("footer",externalGateEvidenceJson.clone());finished=true;close();}catch(IOException|RuntimeException|Error failure){failed=true;throw failure;}
    }
    /** Closing without finish preserves an explicitly incomplete journal. */
    @Override public synchronized void close()throws IOException {
        if(claim!=null)throw new IllegalStateException("journal is exclusively claimed");closeInternal();
    }
}
