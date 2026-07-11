## What this changes

<!-- One or two sentences. If it adds/changes a check, name the OWASP id. -->

## Detection impact

- [ ] New check / heuristic
- [ ] Tightens an existing rule (reduces false positives)
- [ ] Broadens an existing rule (improves recall)
- [ ] No detection change (docs / infra / refactor)

## False-positive profile

<!-- What legitimate servers could look similar? What test pins the benign case? -->

## Checklist

- [ ] `npm run build && npm test` pass locally
- [ ] Added/updated a unit test (and, if relevant, the e2e fixture + assertion)
- [ ] For rule changes: a test pins BOTH a true positive and a benign non-firing case
- [ ] `category` (check family) and `owasp` (Top 10 id) are set correctly and not conflated
