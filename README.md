# asignify

Yet another signify tool

## Purpose

Asignify is a tool to sign and verify messages using public keys cryptography.
It is a rework of OpenBSD `signify` tool but with the following differences:

1. Asignify is portable and self-contained.
2. Asignify **can** use openssl for speed.
3. Asignify has separated high-level library that provides sign and verify API
4. Asignify uses slightly different format of signatures allowing to find out
signature files both by libmagic and humans

However, I plan to be compatible with the original `signify` tool in terms of
checking signatures.

Another significant difference is that `asignify` records **version** and files
**sizes** to allow migrating to another signature schemes than `ed25519`.

## Status

Heavily WIP (**not** for production use)

## Roadmap

- libasignify API
- asignify tool
- compatibility with `signify`
- tests
- documentation
- encryption
