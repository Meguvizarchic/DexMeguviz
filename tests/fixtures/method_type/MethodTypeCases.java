package fixture;
public class MethodTypeCases {
    public static class Target { public Target() {} }
    public static int field;
    public static void sink(String value) { if (value == null) throw new IllegalArgumentException(); }
    public static Object together() { sink("needle"); field = 7; return new Target(); }
    public static void stringOnly() { sink("needle"); }
    public static Object typeOnly() { return new Target(); }
    public static native Object noBody();
}
