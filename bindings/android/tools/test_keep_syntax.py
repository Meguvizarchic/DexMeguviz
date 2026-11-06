"""Fixed-profile keep parser checks; does not invoke R8."""
from jni_classfile import ClassError,verify_keep
engine='-keep class io.github.jichuo1.dexmeguviz.NativeEngine { *; }\n-keep class io.github.jichuo1.dexmeguviz.NativeEngine$* { *; }\n'
graph='-keep class io.github.jichuo1.dexmeguviz.GraphResult { static io.github.jichuo1.dexmeguviz.GraphResult decode(byte[]); }\n'
use=graph.replace('GraphResult','UseGraphResult')
cases=[('original',engine+graph,True),('reordered',' # comment\n'+graph+engine,True),('missing-graph',engine,False),('missing-main',engine.splitlines()[1]+'\n'+graph,False),('missing-nested',engine.splitlines()[0]+'\n'+graph,False),('conditional',engine+'-if class com.example.Missing\n'+graph,False),('allowobfuscation',engine+graph.replace('-keep class','-keep,allowobfuscation class'),False),('allowshrinking',engine+graph.replace('-keep class','-keep,allowshrinking class'),False),('member-only',engine+graph.replace('-keep class','-keepclassmembers class'),False),('wrong-return',engine+graph.replace('GraphResult decode','Object decode'),False),('wrong-argument',engine+graph.replace('byte[]','int[]'),False),('duplicate',engine+graph+graph,False)]
method_type=graph.replace('GraphResult','MethodTypeResult')
cases=[(name,text+use+method_type,expected) for name,text,expected in cases]+[('missing-use',engine+graph+method_type,False),('duplicate-use',engine+graph+use+use+method_type,False),('missing-method-type',engine+graph+use,False),('duplicate-method-type',engine+graph+use+method_type+method_type,False)]
expand=graph.replace('GraphResult','ExpandResult')
cases=[(name,text+expand,expected) for name,text,expected in cases]+[('missing-expand',engine+graph+use+method_type,False)]
advanced=graph.replace('GraphResult','AdvancedResult')
cases=[(name,text+advanced,expected) for name,text,expected in cases]+[('missing-advanced',engine+graph+use+method_type+expand,False)]
method_calls=graph.replace('GraphResult','MethodCallsResult')
cases=[(name,text+method_calls,expected) for name,text,expected in cases]+[('missing-method-calls',engine+graph+use+method_type+expand+advanced,False)]
scope=engine.replace('NativeEngine','ScopedMethodQuery')
cases=[(name,text+scope,expected) for name,text,expected in cases]+[('missing-scoped',engine+graph+use+method_type+expand+advanced+method_calls,False),('missing-scoped-nested',engine+graph+use+method_type+expand+advanced+method_calls+scope.splitlines()[0]+'\n',False),('duplicate-scoped',engine+graph+use+method_type+expand+advanced+method_calls+scope+scope,False)]
annotations=engine.replace('NativeEngine','Annotations')
method_parameters=graph.replace('GraphResult','MethodParametersResult')
cases=[(name,text+method_parameters+annotations,expected) for name,text,expected in cases]+[('missing-method-parameters',engine+graph+use+method_type+expand+advanced+method_calls+scope+annotations,False),('duplicate-method-parameters',engine+graph+use+method_type+expand+advanced+method_calls+scope+annotations+method_parameters+method_parameters,False),('missing-annotations',engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters,False),('duplicate-annotations',engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters+annotations+annotations,False)]
source_export='-keep class io.github.jichuo1.dexmeguviz.DexSourceExport { *; }\n'
cases=[(name,text+source_export,expected) for name,text,expected in cases]+[('missing-source-export',engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters+annotations,False),('duplicate-source-export',engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters+annotations+source_export+source_export,False)]
opcode='-keep class io.github.jichuo1.dexmeguviz.OpcodeQuery { *; }\n'
cases=[(name,text+opcode,expected) for name,text,expected in cases]+[('missing-opcode',engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters+annotations+source_export,False),('duplicate-opcode',engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters+annotations+source_export+opcode+opcode,False)]
scoped_opcode=engine.replace('NativeEngine','ScopedOpcodeQuery')
cases=[(name,text+scoped_opcode,expected) for name,text,expected in cases]+[("missing-scoped-opcode",engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters+annotations+source_export+opcode,False),("duplicate-scoped-opcode",engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters+annotations+source_export+opcode+scoped_opcode+scoped_opcode,False)]
stream_export=source_export.replace('DexSourceExport','DexStreamExport')
valid=engine+graph+use+method_type+expand+advanced+method_calls+scope+method_parameters+annotations+source_export+opcode+scoped_opcode
cases=[(name,text+stream_export,expected) for name,text,expected in cases]+[('missing-stream-export',valid,False),('duplicate-stream-export',valid+stream_export+stream_export,False)]
for name,text,expected in cases:
 try:verify_keep(text);actual=True
 except ClassError:actual=False
 if actual!=expected:raise SystemExit('unexpected keep parser result: '+name)
 print(name,actual)
