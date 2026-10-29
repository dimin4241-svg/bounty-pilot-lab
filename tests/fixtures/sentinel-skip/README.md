# Fixtures: a display rule keyed on a sentinel that carries meaning

`core/src/apps/solana/layout.py` either side of `0fea14829`, "fix(solana): show optional
instruction params by default", shipped in firmware 2.13.0 and published as a paid disclosure.

The removed line is the whole bug:

```python
if property_template.optional and value is None:
    continue
```

The commit says why: "optional params of the instructions of the recognized Solana programs were
never displayed when their value is None, even though **None may encode an action rather than the
absence of one**". In the Token programs' `SetAuthority`, `None` means *remove the authority*.

The fix makes the skip opt in per field - `default_value_to_hide: "none"` in the program
definition - and renders the string `"None"` otherwise. So the qualifier changed from a
**type-level** claim (`property_template.optional`, true of a whole class of fields) to a
**per-field** policy, which is exactly the distinction this generator keys on.
