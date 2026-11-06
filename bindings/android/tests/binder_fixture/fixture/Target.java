package fixture;
public final class Target extends Base {
 static { System.setProperty("dexmeguviz.binder.fixture.initialized", "yes"); }
 public String adapt() { return "not invoked"; }
 public int combine(int value, String[][] text, long[] nums) { return value; }
 public void combine(String value) { }
 public Payload identity(Payload value) { return value; }
 public Payload[][] arrays(Payload[] one, Payload[][] two) { return two; }
 private String hidden(int x) { return "not invoked"; }
}
