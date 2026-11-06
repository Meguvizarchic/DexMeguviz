package fixture;
public class TypeUses {
    public static class Parent { public Parent() {} }
    public static class Child extends Parent { public Child() { super(); } }
    public static Object allocate() { return new Parent(); }
    public static boolean check(Object x) { return x instanceof Parent; }
    public static Parent cast(Object x) { return (Parent) x; }
    public static Class<?> literal() { return Parent.class; }
    public static Object[] array(Object x) { return new Parent[]{(Parent)x, new Parent()}; }
}
