package io.github.jichuo1.dexmeguviz;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/** Verify the JVM-visible Kotlin internal helper cannot accept arbitrary wire names. */
public final class EntityJvmBoundaryTest {
    public static void main(String[] args) throws Exception {
        Method target = null;
        for (Method method : MethodPredicate.Companion.getClass().getDeclaredMethods()) {
            if (!method.getName().startsWith("entityText$")) continue;
            if (target != null || !Modifier.isPublic(method.getModifiers()) ||
                method.getParameterCount() != 5 || method.getParameterTypes()[0] != EntityTextField.class)
                throw new AssertionError("unsafe or duplicate JVM-visible entity text helper");
            target = method;
        }
        if (target == null) throw new AssertionError("JVM-visible entity text helper missing");
        try {
            target.invoke(MethodPredicate.Companion, null, TextOperation.EXACT, "x", false, false);
            throw new AssertionError("null enum accepted");
        } catch (InvocationTargetException expected) {
            if (!(expected.getCause() instanceof NullPointerException)) throw expected;
        }
        try {
            target.invoke(MethodPredicate.Companion, "descriptor\":true,\"bad", TextOperation.EXACT, "x", false, false);
            throw new AssertionError("arbitrary wire accepted");
        } catch (IllegalArgumentException expected) { /* Java reflection rejected wrong parameter type. */ }
        System.out.println("PASS Java-visible entity text helper only accepts closed enum");
    }
}
