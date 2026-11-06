import io.github.jichuo1.dexmeguviz.MethodPredicate;
import io.github.jichuo1.dexmeguviz.MethodTextField;
import io.github.jichuo1.dexmeguviz.TextOperation;

/** Bounds check in a small host heap; stdlib is supplied by the host classpath. */
public final class LimitHost {
    public static void main(String[] args) {
        final MethodPredicate.Companion companion = MethodPredicate.Companion;
        final MethodTextField field = MethodTextField.NAME;
        final TextOperation operation = TextOperation.EXACT;
        final String value = "\uffff".repeat(4_000_000);
        try {
            companion.text(field, operation, value, false);
            throw new AssertionError("oversized predicate accepted");
        } catch (IllegalArgumentException expected) {
            System.out.println("PASS oversized text rejected before JSON expansion");
        } catch (OutOfMemoryError error) {
            System.err.println("OUT_OF_MEMORY during JSON expansion");
            System.exit(42);
        }
    }
}
