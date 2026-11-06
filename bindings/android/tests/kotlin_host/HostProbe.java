import io.github.jichuo1.dexmeguviz.MethodPredicate;
import io.github.jichuo1.dexmeguviz.MethodQuery;
import io.github.jichuo1.dexmeguviz.MethodTextField;
import io.github.jichuo1.dexmeguviz.QueryExecution;
import io.github.jichuo1.dexmeguviz.QueryIntent;
import io.github.jichuo1.dexmeguviz.TextOperation;

/** Plain JVM host: Kotlin runtime is supplied only on the host classpath. */
public final class HostProbe {
    public static void main(String[] args) {
        MethodPredicate p = MethodPredicate.Companion.text(MethodTextField.NAME, TextOperation.EXACT, "locate", false);
        MethodQuery q = new MethodQuery(p, QueryIntent.UNIQUE, 4096, 100000000L);
        if (!q.toQueryIrJson().contains("\"u16\":[108,111,99,97,116,101]")) throw new AssertionError();
        if (QueryExecution.INSTANCE.getSupported()) throw new AssertionError();
        try { QueryExecution.INSTANCE.execute(q); throw new AssertionError(); }
        catch (UnsupportedOperationException expected) { /* no JNI query binding */ }
        System.out.println("PASS plain JVM host supplies Kotlin stdlib, JNI query unsupported");
    }
}
