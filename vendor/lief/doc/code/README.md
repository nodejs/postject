# Documentation code examples

The files in this directory back the code snippets used in the
documentation.

This guarantees that the snippets referenced in the documentation stay in sync with the
actual LIEF API: if an API changes, these files stop compiling/linting and the
error are caught instead of silently staying in the docs.

## Marker convention

Each snippet is wrapped between a pair of marker comments so that
`literalinclude` can extract exactly the region shown in the docs:

```
# lief-doc: <name>-start
<the code the reader sees>
# lief-doc: <name>-end
```

C++ and Rust use `// lief-doc: <name>-start` / `// lief-doc: <name>-end`.

On the documentation side:

```rst
.. literalinclude:: /../code/python/elf.py
   :language: python
   :start-after: lief-doc: parse-start
   :end-before: lief-doc: parse-end
   :dedent:
```

The marker lines themselves are excluded from the generated doc
(`:start-after:` / `:end-before:`), and `:dedent:` strips the leading
indentation coming from the enclosing function.

**Keep the marker around the code** and put every bit of scaffolding
(imports, includes, `None` narrowing, ...) *outside* the marked
region.
