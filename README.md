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

## Upcoming work
- Implementation of less-performant solution as a fallback for unsupported compressors
- Implementation of MS Office compressor
- Optimization of pointer file structure
- Unit and integration testing
- Extending documentation
- Rewriting to rust