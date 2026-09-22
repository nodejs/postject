---
description: Read LIEF documentation as resolved Markdown or retrieve guides and API symbols from versioned JSON indexes with canonical links and content hashes.
---

# {fa}`fa-solid fa-robot` Documentation for AI

Every documentation page has a Markdown copy at the same path with `.html`
replaced by `.md`. For example, `runtime/intro.html` has a `runtime/intro.md`
copy. The HTML page advertises this copy with an alternate link in its head,
following the [llms.txt proposal](https://llmstxt.org/).

The Markdown contains the rendered documentation: code included from example
files, every language tab, API signatures, tables, and notes. Links and image
URLs are absolute, so content remains usable when read outside this website.
Section and API headings link to their original HTML anchors for citation.

## Choose a resource

These files are generated alongside each version of the documentation:

| Resource | Use it to |
| --- | --- |
| [`llms.txt`](llms.txt) | Find the relevant guide or API page, with a description of each page |
| [`index.json`](index.json) | Search document titles, descriptions, and full text, then fetch a Markdown page |
| [`index.chunks.json`](index.chunks.json) | Retrieve individual sections or API symbols with their heading context and citation URLs |
| [`llms-full.txt`](llms-full.txt) | Download all Markdown pages, including API references, for local indexing |
| [`objects.inv`](objects.inv) | Look up documented symbols by name |
| [`sitemap.xml`](sitemap.xml) | Enumerate canonical HTML pages |

Start with `llms.txt` and fetch the pages relevant to the task. The full corpus
includes large API references; it may exceed an assistant's context window.
The exported corpus covers the Sphinx documentation. The API guides also link
to the separate Rust and Doxygen references.

## Match the documentation to the installation

Markdown metadata and JSON records carry `documentationVersion`,
`documentationChannel`, `canonical`, and `markdownURL`. The `latest` channel
tracks development; `stable` tracks the latest release. Match API usage to the
installed LIEF version, platform, architecture, and enabled features.

Use the {doc}`installation` guide to choose a build. Read {doc}`extended/intro`
for Extended features and {doc}`runtime/intro` for runtime availability. Basic
runtime support is an independent build option. Memory-layout enumeration,
assembly, and disassembly require Extended.

## Retrieve and update chunks

Both JSON indexes declare a `schemaVersion`. Each chunk contains Markdown and
plain text, its document title and description, a `headingPath`, and a `url`
pointing to the canonical HTML section or API symbol. Chunk sizes follow the
documentation structure; code blocks stay intact.

`documentID` identifies a canonical page, including its version channel.
`chunkID` identifies a section within that page. These IDs remain stable across
builds when the page URL and section anchor stay the same. `position`,
`documentChunkCount`, `previousChunkID`, and `nextChunkID` allow retrieval of
surrounding context. Positions start at zero; neighbors are empty strings at
document boundaries.

Compare the index's `corpusHash` to detect changes to content or metadata, then
compare individual `contentHash` values to find changed Markdown bodies. Both
use SHA-256. The chunk index describes the hash inputs and ordering. Build
timestamps are excluded so unchanged content produces the same indexes.
