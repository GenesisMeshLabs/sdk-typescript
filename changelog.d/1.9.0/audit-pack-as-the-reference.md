### Fixed

Found by comparing this SDK with the Python reference and the .NET SDK on the reference-judged audit pack, report, changes file and anchor cases:

- **A report writes numbers and IDs as the reference does.** A number written as a float stays one: a cell writes `1e+16` where its value is an integer of 2^53 or more (it wrote the digits), and an ID or a denial reason `1.0`, not `1`, so an observation keyed `1.0` finds its judgement. A reason or ID that is a list or an object is Python's `str()` of it (`{'why': ['x']}`, where it wrote `[object Object]` or the items joined by commas). A pack whose report holds such a value no longer fails as `report_mismatch`.
- **A CSV changes file is read as Python's `csv` module reads it.** A quote opens a quoted field only at the start of a field (elsewhere it is text: `r1, "rotate"` is `"rotate"`, where it read `rotate`), a quote closing a field followed by other text joins it, and the header is the first line, a blank one included (it skipped one). A carriage return inside a line outside quotes, and a field longer than 131072 characters, are refused, as the reference's `csv.Error`; a lone carriage return no longer ends a line.
- **A changes file's values are trimmed as Python trims them:** U+001C to U+001F and U+0085 included, U+FEFF kept.
- **An audit pack manifest whose signature holds a field besides `key_id` and `sig`** is not in the NA's form: `manifest_invalid`, as the reference reads it (it was accepted).
- **A store anchor whose integers are written as floats** (`1.0`) verifies, as the reference reads it; its signature failed.
