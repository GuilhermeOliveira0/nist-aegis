---
type: regex
target: files
pattern: '^(?!.*security-audit[\\/]).+$'
flags: m
match: not_contains
weight: 2
---
