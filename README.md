# docx-git-extension-python (WIP)

## General information
The Docx Git Extension is designed to dramatically `improve the efficiency of storing often-changing docx files`.

Git can very efficiently store many versions of, e.g., a text file, because it is only storing the changes between files. However, docx files are a zipped collection of xml files and assets (e.g. images). Git is famously bad at storing versioned zip files because a single character change to the unzipped contents results in a completely different compressed zip. Thus, a single-character change to the contents of a 50mb zip will result in the repository growing by 50 megabytes.

The Docx Git Extension resolves this by transparently unzipping the docx file just prior to commit and rezipping it just prior to checkout. It tracks all metadata necessary for a reproducible zip, thus ensuring that a hash of the docx before and after this round trip is identical (reproducible zipping).

The Docx Git Extension implements `clean/smudge filters and post-commit hook` to transparently unzip/zip the docx files. It stores the unzipped contents of the docx files as a git tree referenced by custom refs. Currently, it is written in Python and the goal is to convert it to rust to maximize performance and portability and to package it as a GitHub extension for easy installation and distribution.

The extension currently handles docx files created by `python-docx` and `aspose`. It uses tuned `zlib` compressor to match the compression algorithm of the fore-mentioned docx creators.

Additionally, the extension can be upgraded to support any zip-based file format by reproducing its compressor performance. However, if compressor performance is not matched, pointer file can be extended to store additional metadata and therefore allow custom, deterministic recompression at low level. This solution is less performant, but can be used for `storing any zip-based file format`.

## Structure
The extension contains a set of python scripts that are embedded into git workflows:
- clean filter script
- smudge filter script
- post-commit hook script

## Pointer file
Git stores a short text pointer in place of each document; the parts live in a separate git tree. Format 1.0:

```
DOCX-POINTER placeholder - this repository stores documents unpacked; ...
VERSION 1.0
TREE be10c2f9ce2dfb27c12dd4b063685180d95e04eb
HASH da7da6feb0040ed37ce506aa4e8af859fedb97de87a5212b615bd97bdc6df544
PROFILE aspose-ml#8
DEFAULTS ver=20 flags=0 method=8 time=45532 date=23880 made=45 cdver=20 cdtime=45532 cddate=23880 iattr=0 eattr=0 dd=0 lextra= cextra= comment=
ENTRY [Content_Types].xml
ENTRY word/document.xml
ENTRY word/media/image1.jpeg breaks=18525,18598,62256,132156,20333,81003
```

- One line per zip entry, in archive order; an entry lists only the header fields that differ from `DEFAULTS`.
- `flush=` (Word) and `breaks=` (other packagers) are gaps: the first number is the offset from the start of the part, each next one the distance from the previous.
- Byte fields are hex, with runs of 4+ zero bytes written `(N)`; names escape bytes outside printable ASCII, space and `%` as `%XX`.
- A zip with its own comment gets an `ARCHIVE comment=<hex>` line before `DEFAULTS`; other documents have no `ARCHIVE` line.
- `pointer_format.py` holds the full specification, the writer and the parser, shared by clean and smudge.

**Versioning.** `VERSION <major>.<minor>` is always the second line. A minor increase only adds information an older reader can ignore without rebuilding different bytes; anything that changes how a document is rebuilt is a new major, and a reader refuses a major it does not know. Pointers from before 1.0 (no `VERSION` line) are refused; re-add them with `git add --renormalize .` and commit.

## Compression profiles
Every pointer names the profile its document is rebuilt with (`PROFILE <name>`), so checkout rebuilds once and never searches. Clean picks the profile:

- Word candidate (`msword`) when every deflated part ends with a flush; Word's mid-part flush offsets are read with libz.
- Otherwise the zlib profiles (`python-docx`, `aspose-ml#1`..`#9`), tried in order of how much of the largest part each reproduces, with block breaks fitted where needed.
- Every comparison streams the compressor's output and stops at the first block that differs; a candidate is dropped at the first part it cannot reproduce, largest part first. The break fitter resumes from its last confirmed break, so its cost grows with the part's size, not with size times breaks, and it has no limit on the number of breaks.

`PROFILE fallback` means no profile reproduced the document (SharePoint and Word for the web, Info-ZIP, anything new). Those documents use the fallback below.

## Fallback compression (preflate)
For a `PROFILE fallback` document, clean asks [preflate-rs](https://github.com/microsoft/preflate-rs) to model every deflated part. It records the difference from its prediction, typically 40-80 bytes per part, as `preflate=<base64>` on the part's `ENTRY` line, plus the version that made it:

```
PROFILE fallback
FALLBACK preflate-rs/0.7.6
ENTRY word/document.xml time=12106 date=23898 preflate=AAAEDAAEIAE+AP8DAQQAAAQQBAQDAA4AIDDw9zrPvwsT0D2gHJ4=
```

Smudge rebuilds those parts from the plain part plus its corrections, byte for byte. The corrections format changes between preflate-rs releases, so smudge refuses to use a helper of another version than the pointer names.

preflate-rs runs in a small Rust helper, `preflate-helper/` (`docx-preflate`, pure Rust; needs Rust 1.89 or newer). Build it once per machine:

```
cargo build --release --manifest-path preflate-helper/Cargo.toml
```

It is found at `$DOCX_PREFLATE`, then `preflate-helper/target/release/`, then on `PATH`; `python3 preflate_fallback.py` prints which one is used. One helper process handles a whole document, its parts in parallel. Clean verifies every correction by rebuilding the stream inside the helper, so nothing is recorded that would not rebuild.

Without the helper, clean warns and stores the document without corrections; it will not check out byte-identical until re-added with the helper built. A part preflate cannot model is reported the same way.

## Images in Git LFS
Document parts can be kept in Git LFS instead of the git object store. It is opt-in per document path, with an attribute next to the filter:

```
*.docx filter=docx docx-lfs=jpg,jpeg
```

The value lists part extensions (a bare `docx-lfs` means `jpg,jpeg`). Without it nothing changes - pointers stay byte-identical to before.

- **clean** writes each matching part to the local LFS store (`.git/lfs/objects`) and puts the standard three-line LFS pointer in the parts tree. No `git lfs` process is started.
- **smudge** reads pointers back from the local store and fetches only missing objects, through `git lfs smudge`, several at a time. Endpoint and credentials come from `.lfsconfig` and your credential helper as usual.
- **push** needs nothing extra: `git lfs pre-push` scans the pushed `refs/docx/*` commits and uploads the images. Use a plain `git push` so the configured refspecs (`HEAD`, `refs/docx/*`) are pushed together.

In a fresh clone, `git lfs fetch --all origin` after fetching `refs/docx/*` downloads every image in one batch before checkout; otherwise smudge downloads what it needs on demand. See `lfs_parts.py` for details.

## Upcoming work
- Structural check in clean: compare local and central headers, gaps between entries, data after the archive, zip64 and other rebuild assumptions, and record (on the `ARCHIVE` line) or report what does not fit instead of failing at checkout.
- Last-resort tier for a part preflate cannot model: keep its compressed bytes as a blob.
- Long-running filter (`filter.process`): ~0.13 s of a small document's clean is interpreter and pygit2 start-up, about an hour per 30k documents; git's delayed checkout in that protocol also lets smudge rebuild documents in parallel.
- Cache of fitted breaks and preflate corrections keyed by the compressed part's SHA-256 and the profile, so unchanged parts and repeated images skip the work on re-add and renormalize.
- Unpack and rebuild in memory: clean writes the document to a temp folder, unpacks it and inflates every part again for the profile check (0.83 s of a 17 MB document's clean); smudge extracts the tree to a temp folder and reads it back.
- More known profiles where producers are common (.NET packaging, zlib-ng from Word for the web), so fewer documents need the fallback.
- `docx-lfs` for PNG and EMF as well as JPG: the largest parts in the samples are a 6.7 MB EMF and a 3.2 MB PNG.
- Container layout keyed by content hash (two-character fanout, split further past 1024 entries).
- Unit and integration testing
- Extending documentation
- Rewriting to Rust (links preflate-rs directly instead of the helper)
