# Static class-annotation DEX fixture

`inner-flags.dex` is compiled from the adjacent project-authored `InnerFlagsCases.java` with `generate_fixture.py`; it is a fixed test input, not a claim about ART or a real application. SHA-256: `11adcfeeb6d76f655a590303088ede73285a1aeffa619ccf268e456fa8bec6ee`.

To regenerate, invoke the generator with `--source` pointing to the Java file, `--java` to a JDK 17 `java`, `--d8` to Android build-tools 37.0.0 `d8.jar`, `--expected-sha256` set to the digest above and `--output` to a new directory. The generator records exact commands and the before/after hashes of itself, source, and tools; it never deletes an existing directory. JDK and D8 versions can change output bytes, so a different toolchain is not assumed equivalent.

CTest registers `class_annotation_boundary`, `class_annotation_c` and `class_annotation_oracle`. The latter verifies the fixture hash, runs the independent byte oracle with the newly built CLI, and retains a unique per-run receipt directory under the build tree; the receipt binds actual arguments, interpreter, CLI, fixture, oracle and output hashes. Generated files and evidence can accumulate; cleanup requires the workspace's normal policy.
