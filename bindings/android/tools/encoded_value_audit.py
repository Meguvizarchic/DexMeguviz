"""Classfile checks for the pure-Java EncodedValue API; no JNI entrypoints."""
from jni_classfile import ClassError, require_field, require_method

ENCODED_VALUE_CLASSES=['EncodedValue','EncodedValue$Limits','EncodedValue$DecodeException',
                       'EncodedValue$Element','EncodedValue$Value','EncodedValue$Parser']

def check_encoded_value_class(clazz,name):
 prefix=b'io/github/jichuo1/dexmeguviz/'
 if name not in ENCODED_VALUE_CLASSES or clazz['name']!=prefix+name.encode('ascii'):
  raise ClassError('encoded value class identity')
 expected_flags=0x30 if name=='EncodedValue$Parser' else 0x31
 expected_parent=b'java/lang/IllegalArgumentException' if name=='EncodedValue$DecodeException' else b'java/lang/Object'
 if clazz['flags']!=expected_flags or clazz['superclass']!=expected_parent:
  raise ClassError('encoded value class access or superclass')
 methods={
  'EncodedValue':[(b'decode',b'([BL'+prefix+b'EncodedValue$Limits;)L'+prefix+b'EncodedValue$Value;',9)],
  'EncodedValue$Limits':[(b'<init>',b'(III)V',1)],
  'EncodedValue$Value':[(b'originalBytes',b'()[B',1),(b'integerValue',b'()J',1),(b'floatingRawBits',b'()J',1),
   (b'referenceIndex',b'()J',1),(b'booleanValue',b'()Z',1),(b'arraySize',b'()I',1),
   (b'arrayValue',b'(I)L'+prefix+b'EncodedValue$Value;',1),(b'annotationTypeIndex',b'()J',1),
   (b'annotationSize',b'()I',1),(b'annotationElement',b'(I)L'+prefix+b'EncodedValue$Element;',1)]}
 fields={
  'EncodedValue':[(n.encode('ascii'),b'I',25) for n in 'BYTE SHORT CHAR INT LONG FLOAT DOUBLE METHOD_TYPE METHOD_HANDLE STRING TYPE FIELD METHOD ENUM ARRAY ANNOTATION NULL BOOLEAN'.split()],
  'EncodedValue$Limits':[(n.encode('ascii'),b'I',17) for n in 'maxBytes maxNodes maxDepth'.split()],
  'EncodedValue$Value':[(b'kind',b'I',17),(b'valueArg',b'I',17)],
  'EncodedValue$Element':[(b'nameIndex',b'J',17),(b'value',b'L'+prefix+b'EncodedValue$Value;',17)]}
 expected_methods=methods.get(name,[]); expected_fields=fields.get(name,[])
 for n,d,a in expected_methods: require_method(clazz,n,d,a)
 for n,d,a in expected_fields: require_field(clazz,n,d,a)
 if {(m['name'],m['descriptor'],m['access']) for m in clazz['methods'] if m['access']&1}!=set(expected_methods):
  raise ClassError('unexpected public encoded value method')
 if {(f['name'],f['descriptor'],f['access']) for f in clazz['fields'] if f['access']&1}!=set(expected_fields):
  raise ClassError('unexpected public encoded value field')
