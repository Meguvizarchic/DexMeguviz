package fixture;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) @Target({ElementType.TYPE,ElementType.FIELD,ElementType.METHOD,ElementType.PARAMETER}) @interface Mark { String value(); }
@Retention(RetentionPolicy.RUNTIME) @interface Nested { String value(); }
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) @interface Complex { int n(); String str(); int[] ints(); Nested nested(); Class<?> type(); }
@Mark("class") @Complex(n=-7,str="雪",ints={1,2},nested=@Nested("x"),type=String.class)
public class Annotated { @Mark("field") public int value; @Mark("method") public void run(@Mark("parameter") String value) {} public void plain() {} }
