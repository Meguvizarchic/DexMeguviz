package io.github.jichuo1.dexmeguviz.precompute;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Adapted from the project's bounded JSON reader. Escaped isolated UTF-16
 * units are intentionally preserved to match QueryIR and Python ensure_ascii. */
final class OfflineJson {
    static void need(boolean condition,String status,String message){if(!condition)throw new PrecomputedCandidates.Failure(status,message);}
    static Object parse(byte[] bytes,Budget budget){need(bytes.length<=16*1024*1024,"BudgetExceeded","JSON bytes");try{return new Parser(StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(),budget).parse();}catch(java.nio.charset.CharacterCodingException e){throw new PrecomputedCandidates.Failure("InvalidPackage","invalid UTF-8 JSON");}}
    @SuppressWarnings("unchecked") static Map<String,Object> obj(Object v){need(v instanceof Map,"InvalidPackage","object required");return (Map<String,Object>)v;}
    @SuppressWarnings("unchecked") static List<Object> arr(Object v){need(v instanceof List,"InvalidPackage","array required");return (List<Object>)v;}
    static String str(Object v){need(v instanceof String,"InvalidPackage","text required");return (String)v;}
    static long num(Object v){need(v instanceof BigInteger,"InvalidPackage","integer required");BigInteger value=(BigInteger)v;need(value.compareTo(BigInteger.valueOf(Long.MIN_VALUE))>=0&&value.compareTo(BigInteger.valueOf(Long.MAX_VALUE))<=0,"InvalidPackage","integer range");return value.longValue();}
    static boolean bool(Object v){need(v instanceof Boolean,"InvalidPackage","boolean required");return (Boolean)v;}
    static BigInteger n(long n){return BigInteger.valueOf(n);}
    static Map<String,Object> map(Object... pairs){Map<String,Object> out=new LinkedHashMap<>();for(int i=0;i<pairs.length;i+=2)out.put((String)pairs[i],pairs[i+1]);return out;}
    static void equal(Object a,Object b,String status,String message){need(Objects.equals(a,b),status,message);}
    static Object freeze(Object v){if(v instanceof Map){Map<String,Object> out=new LinkedHashMap<>();for(Map.Entry<String,Object> e:obj(v).entrySet())out.put(e.getKey(),freeze(e.getValue()));return Collections.unmodifiableMap(out);}if(v instanceof List){List<Object> out=new ArrayList<>();for(Object x:arr(v))out.add(freeze(x));return Collections.unmodifiableList(out);}return v;}
    private static int compareKeys(String a,String b){int x=0,y=0;while(x<a.length()&&y<b.length()){int c=a.codePointAt(x),d=b.codePointAt(y);if(c!=d)return Integer.compare(c,d);x+=Character.charCount(c);y+=Character.charCount(d);}return Integer.compare(a.length()-x,b.length()-y);}
    static byte[] canonical(Object v,Budget budget){StringBuilder b=new StringBuilder();emit(v,b,budget,0);return b.toString().getBytes(StandardCharsets.US_ASCII);}
    private static void emit(Object v,StringBuilder b,Budget budget,int depth){budget.charge(1);need(depth<=64&&b.length()<=16*1024*1024,"BudgetExceeded","canonical JSON bound");
        if(v==null)b.append("null");else if(v instanceof Boolean||v instanceof BigInteger)b.append(v.toString());else if(v instanceof String)quote((String)v,b,budget);
        else if(v instanceof List){b.append('[');boolean first=true;for(Object x:arr(v)){if(!first)b.append(',');first=false;emit(x,b,budget,depth+1);}b.append(']');}
        else if(v instanceof Map){b.append('{');List<String> keys=new ArrayList<>(obj(v).keySet());keys.sort(OfflineJson::compareKeys);boolean first=true;for(String k:keys){if(!first)b.append(',');first=false;quote(k,b,budget);b.append(':');emit(obj(v).get(k),b,budget,depth+1);}b.append('}');}
        else throw new PrecomputedCandidates.Failure("InvalidPackage","unsupported JSON value");need(b.length()<=16*1024*1024,"BudgetExceeded","canonical JSON bytes");}
    private static void quote(String value,StringBuilder b,Budget budget){final char[] hex="0123456789abcdef".toCharArray();b.append('"');for(int i=0;i<value.length();i++){if((i&1023)==0)budget.check();char c=value.charAt(i);switch(c){case '"':b.append("\\\"");break;case '\\':b.append("\\\\");break;case '\b':b.append("\\b");break;case '\t':b.append("\\t");break;case '\n':b.append("\\n");break;case '\f':b.append("\\f");break;case '\r':b.append("\\r");break;default:if(c<32||c>=127)b.append("\\u").append(hex[(c>>12)&15]).append(hex[(c>>8)&15]).append(hex[(c>>4)&15]).append(hex[c&15]);else b.append(c);}need(b.length()<=16*1024*1024,"BudgetExceeded","canonical string limit");}b.append('"');}
    private static final class Parser {
        final String input;final Budget budget;int at,nodes;
        Parser(String input,Budget budget){this.input=input;this.budget=budget;}
        Object parse(){Object out=value(0);ws();need(at==input.length(),"InvalidPackage","trailing JSON");return out;}
        void ws(){while(at<input.length()&&" \t\r\n".indexOf(input.charAt(at))>=0)at++;}
        boolean take(char c){ws();if(at<input.length()&&input.charAt(at)==c){at++;return true;}return false;}
        void node(int depth){budget.charge(1);need(depth<=64&&++nodes<=200000,"BudgetExceeded","JSON shape limit");}
        Object value(int depth){node(depth);ws();need(at<input.length(),"InvalidPackage","truncated JSON");char c=input.charAt(at);
            if(c=='{'){at++;Map<String,Object> out=new LinkedHashMap<>();if(take('}'))return out;do{ws();node(depth+1);String key=string();need(take(':')&&!out.containsKey(key),"InvalidPackage","JSON key or colon");out.put(key,value(depth+1));}while(take(','));need(take('}'),"InvalidPackage","object end");return out;}
            if(c=='['){at++;List<Object> out=new ArrayList<>();if(take(']'))return out;do{out.add(value(depth+1));}while(take(','));need(take(']'),"InvalidPackage","array end");return out;}
            if(c=='"')return string();if(input.startsWith("true",at)){at+=4;return Boolean.TRUE;}if(input.startsWith("false",at)){at+=5;return Boolean.FALSE;}if(input.startsWith("null",at)){at+=4;return null;}
            int start=at;if(c=='-')at++;need(at<input.length(),"InvalidPackage","number");if(input.charAt(at)=='0')at++;else{need(input.charAt(at)>='1'&&input.charAt(at)<='9',"InvalidPackage","integer number");while(at<input.length()&&input.charAt(at)>='0'&&input.charAt(at)<='9')at++;}need(at-start<=4300,"BudgetExceeded","number digits");return new BigInteger(input.substring(start,at));}
        String string(){need(at<input.length()&&input.charAt(at++)=='"',"InvalidPackage","JSON string");StringBuilder out=new StringBuilder();while(at<input.length()){char c=input.charAt(at++);if(c=='"'){String value=out.toString();need(value.codePointCount(0,value.length())<=1048576,"BudgetExceeded","JSON string length");budget.text(value.length());return value;}need(c>=32,"InvalidPackage","JSON control");if(c!='\\')out.append(c);else{need(at<input.length(),"InvalidPackage","escape");char e=input.charAt(at++);switch(e){case '"':case '\\':case '/':out.append(e);break;case 'b':out.append('\b');break;case 't':out.append('\t');break;case 'n':out.append('\n');break;case 'f':out.append('\f');break;case 'r':out.append('\r');break;case 'u':need(at+4<=input.length(),"InvalidPackage","unicode escape");int unit=0;for(int i=0;i<4;i++){char h=input.charAt(at++);int v=h>='0'&&h<='9'?h-'0':h>='a'&&h<='f'?h-'a'+10:h>='A'&&h<='F'?h-'A'+10:-1;need(v>=0,"InvalidPackage","hex escape");unit=(unit<<4)|v;}out.append((char)unit);break;default:throw new PrecomputedCandidates.Failure("InvalidPackage","JSON escape");}}if((out.length()&1023)==0)budget.check();need(out.length()<=2097152,"BudgetExceeded","JSON UTF-16 units");}throw new PrecomputedCandidates.Failure("InvalidPackage","unterminated JSON string");}
    }
}
