package fixture;
public class MemberTarget {
 static { System.setProperty("dexmeguviz.member.fixture.initialized","yes"); }
 public int instanceField;
 public static long staticField;
 private Payload[] payloads;
 public Payload[][] matrix;
 private MemberTarget() { }
 public MemberTarget(int value,Payload[][] values) { }
 public MemberTarget(Payload[] values) { }
}
