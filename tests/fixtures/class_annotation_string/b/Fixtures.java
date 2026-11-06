package stringfixture;
import java.lang.annotation.*;
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.TYPE) @interface Tag { String value(); }
@Tag("bbbb") class Collision {}
@Tag("") class Empty {}
@Tag("\u96ea") class Snow {}
@Tag("\ud83d\ude00") class Face {}
@Tag("\ud800") class Lone {}
@Tag("a\000b") class Nul {}
class Absent {}
