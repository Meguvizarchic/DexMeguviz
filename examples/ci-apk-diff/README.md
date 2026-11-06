# Static APK/DEX diff in CI

Build the host CLI for the runner, keep the compared files immutable, then run:

```sh
python cli/diff/dexdiff.py --exe "$DEXMEGUVIZ_CLI" --before "$OLD_BASE" --after "$NEW_BASE" "$NEW_SPLIT" --output static-diff.json
```

The output file is replaced atomically only after a complete comparison. A nonzero exit leaves any existing output in place; it may therefore contain an older result and must not be treated as the current run. The output directory must exist and have no concurrent writer. The default source scopes are incomplete; add `--before-complete` or `--after-complete` only when the calling pipeline can justify that assertion. Differences are reported as counts and occurrence evidence; exit 0 means the comparison completed, not that the versions are equivalent or that a change is safe. A caller-specific policy must inspect the JSON and decide its own gate. Add `--code-digest` to compare raw code-item bytes, noting the pool-index and semantic limitations described in the contract.

The command is independent of Android and BIL. It reports symbols observed in the supplied APK/DEX files; it does not establish ClassLoader binding or runtime dispatch. See `docs/contracts/cli-static-diff-v1.md` for bounds and resource-only inputs.


For an additional static view of whether each local reference has matching definitions in other supplied source occurrences, add `--reference-candidates`. The extra counts remain observations in the declared source scope; they do not prove ART or ClassLoader resolution. See the `Optional cross-source reference candidates` section of the contract.
