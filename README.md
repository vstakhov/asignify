# asignify

Yet another signify tool

## Introduction

Asignify tool is heavily inspired by [signify](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/signify) used in OpenBSD.
However, the main goal of this project is to define high level API for signing files
and validating signatures. Asignify is designed to be portable and self-contained
with zero external dependencies. It uses [blake2b](https://blake2.net/) as the main
hash function and ed25519 implementation from [tweetnacl](http://tweetnacl.cr.yp.to/).

Asignify can verify OpenBSD signatures but it cannot sign messages in OpenBSD format yet.

## Cryptographic basis

Asignify relies on the same primitives as `signify` utility, however, for the native format
asignify uses `blake2` cryptographic hash function instead of `sha512`. I decided this
mainly because of the performance of `blake2`. Since this function was in the final of
SHA3 competition (along with the current `keccak` winner), I believe that it is secure
enough for using as collisions resistant hash function. Moreover, unlike sha2, blake2 is 
not vulnerable to extensions attacks.

For digital signatures `asignify` uses `ed25519` algorithm which is blazingly fast and
proven to be secure even without random oracle (based on Schnorr scheme). `tweetnacl` library
is very small and precisely analysed.

To sign a file, `asignify` does the following steps:

1. Calculates digest of a file (e.g. `blake2` or `sha512`)
2. Opens secret key file (decrypting it if needed)
3. Write all digests to the output buffer in format:

	sha256 (filename) = deadbeef....
	size (filename) = 666
	...

4. Calculates ed25519 signature over using secret key and the following fields:

	version
	data

5. Afterwards, a signature is packed into `asignify` signature line and prepended
to the digests content

To verify signature, `asignify` loads public key, verifies the signature in the same
way, load files digests and verify corresponding files agains these digests.

Hence, `asignify` only sign digests of files and not files themselves, and a signature
contains both digests and its ed25519 signature.

## Keys storage

Secret key for `asignify` can be encrypted using password-based key derivation function,
namely `pbkdf2-blake2`. This function can be tuned for the number of rounds to increase
amount of work required for an adversary to brute-force the encryption password into
a valid encryption key.

Currently, `asignify` uses the following fields for private key:

~~~
asignify-private-key
version: 1
data: <hex_blob|64 bytes>
id: <hex_blob|64 bytes>
kdf: pbkdf2-blake2
rounds: 42000
salt: <hex_blob|16 bytes>
checksum: <hex_blob|64 bytes>
~~~

Checksum is used to validate password against the original encryption key. The current
minimum rounds count is 10000, however, it can be changed in future.

Public keys and signatures has nearly the same format:

~~~
magic:version:<b64_key_id>:<b64_key_data>
asignify-pubkey:1:kEjp3MrX5fE=:Hut...bl/mQ=
asignify-sig:1:kEjp3MrX5fE=:Sfg...A==
~~~

Key id is used to match keypairs and the corresponding signatures.

## Libasignify API

`libasignify` provides high level API for the most common signature operations.

To verify a signature you should do the following:

~~~C
/* Init context */
vrf = asignify_verify_init();

/* Load pubkey */
if (!asignify_verify_load_pubkey(vrf, pubkeyfile)) {
	errx(1, "cannot load pubkey %s: %s", pubkeyfile,
		asignify_verify_get_error(vrf));
}

/* Load and verify digests file */
if (!asignify_verify_load_signature(vrf, sigfile)) {
	errx(1, "cannot load signature %s: %s", sigfile,
		asignify_verify_get_error(vrf));
}

/* Verify files with digests */
for (i = 0; i < argc; i ++) {
	if (!asignify_verify_file(vrf, argv[i])) {
		errx(1, "cannot verify file %s: %s", argv[i],
			asignify_verify_get_error(vrf));
	}
}

/* Cleanup */
asignify_verify_free(vrf);
~~~

To sign files, you should provide callback for password prompt (e.g. by BSD function
`readpassphrase`):

~~~C
static int
read_password(char *buf, size_t len, void *d)
{
	char password[512];
	int l;

	if (readpassphrase("Password:", password, sizeof(password), 0) != NULL) {
		l = strlen(password);
		memcpy(buf, password, l);
		
		/* Securely clean password data */
		explicit_memzero(password, sizeof(password));

		return (l);
	}

	return (-1);
}
~~~

If you want to use unencrypted private keys, then just pass NULL as a password
callback when trying to open a secret key file.

Afterwards, signing is not so hard:

~~~C

/* Init sign context */
sgn = asignify_sign_init();

/* Load encrypted private key with the provided password callback */
if (!asignify_sign_load_privkey(sgn, seckeyfile, read_password, NULL)) {
	errx(1, "cannot load private key %s: %s", seckeyfile,
		asignify_sign_get_error(sgn));
}

/* Add files digests */
for (i = 0; i < argc; i ++) {
	if (!asignify_sign_add_file(sgn, argv[i], ASIGNIFY_DIGEST_BLAKE2)) {
		errx(1, "cannot sign file %s: %s", argv[i],
			asignify_sign_get_error(sgn));
	}
}

/* Sign digests and write everything to a file */
if (!asignify_sign_write_signature(sgn, sigfile)) {
	errx(1, "cannot write sign file %s: %s", sigfile,
		asignify_sign_get_error(sgn));
}

/* Cleanup */
asignify_sign_free(sgn);
~~~

Generating of keypairs is served by `libasignify` as well:

~~~C
if (!asignify_generate(seckeyfile, pubkeyfile, 1, rounds,
		read_password_verify, NULL)) {
	errx(1, "Cannot generate keypair");
}
~~~

Specifying `NULL` as password callback leads to unencrypted secret keys being produced.


## Supported digests format

- SHA256
- SHA512
- BLAKE2b

For sha2 `libasignify` can use openssl if it is available in the system since it
provides highly optimized versions of SHA allowing to calculate checksums much quicker
than sha2 code embedded into `libasignify`.

## OpenBSD signatures

`libasignify` automatically recognises and parses OpenBSD signatures and public keys allowing
thus to verify signatures produced by `signify` utility transparently. Secret keys and signing
is currently unsupported, however such a support is planned in the future.

## Roadmap

- Better OpenBSD compatibility
- Better CLI
- Manpages and other docs
- Fuzz testing
- Encryption via ed25519 <-> curve25519 transform

## Status

Heavily WIP (**not** for production use)
