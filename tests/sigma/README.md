# Sigma test events

`run_tests.py` checks Sigma rules against sample events, so a rule is tested for what it matches and not only for its syntax.

```bash
python3 tests/sigma/run_tests.py
```

## Adding test events for a rule

Create `fixtures/<rule file name without .yml>.jsonl`, with one JSON object per line:

```json
{"name": "what this case shows", "expected": true, "event": {"Image": "/usr/bin/nmap", "ParentImage": "/bin/zsh"}}
```

- `event` uses the field names the rule uses. For `process_creation` rules those are `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine` and the like.
- `expected` is `true` when the rule must match the event and `false` when it must not.
- Every file needs at least one match and one near miss. Near misses are the valuable part: the event that looks close and must stay quiet.
- Events are synthetic. No customer data, real user names, internal host names or internal addresses.
- Keep events self-contained: plain field values, with no references to other tools, products or outside links.

The rule is parsed by pySigma and evaluated with Sigma's own matching rules: a value matches the whole field unless a modifier adds wildcards, and string matching ignores case. Correlation rules are not evaluated.
