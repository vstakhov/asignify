# asignify

Yet another signify tool

## Introduction

Asignify is heavily inspired by [signify](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/signify), used in OpenBSD.
However, the main goal of this project is to define a high-level API for signing files,
validating signatures and encrypting files using public key cryptography. 
Asignify is designed to be portable and self-contained with zero external dependencies. It uses [blake2b](https://blake2.net/) as the hash function and the ed25519 implementation from [tweetnacl](http://tweetnacl.cr.yp.to/).

Asignify can verify OpenBSD signatures (but it cannot sign messages in OpenBSD format yet).

## Key Features

- Zero dependencies (libc and C compiler are likely required though), so it could be easily used in embedded systems
- Modern cryptography primitives (ed25519, blake2 and sha512 namely)
- The ability to encrypt files with the same keys using curve25519-based [cryptobox](http://nacl.cr.yp.to/box.html).
- Protecting secret keys with passwords using PBKDF2-BLAKE2 routines
- `asignify` can convert ssh ed25519 private keys to the native format and verify signatures using just ssh ed25519 public keys (without intermediate conversions)
- `asignify` is designed to be fast and portable. It is faster than many state-of-art tools, for example, gpg:

```
Intel(R) Core(TM)2 Quad CPU    Q6600  @ 2.40GHz (-O3)

asignify encrypt sec1 sec2.pub test   7,66s user 2,48s system 88% cpu 11,482 total
gpg --encrypt --sign -r bob@example.com test   20,61s user 0,51s system 99% cpu 21,197 total
```

- `asignify` provides a high-level API to application developers for signing, verifying, encrypting and
key generation
- All keys, signatures and encrypted files contain version information, allowing changes to
cryptographical primitives in the future without loss of backward compatibility.

## Usage Examples

Here are some (descriptive) usage examples of the `asignify` utility:

- Get help for a the tool:

```
$ asignify help
$ asignify help <command>
```

- Generate a Keypair:

```
$ asignify generate privkey
$ asignify generate --no-password privkey pubkey
```

- Convert an SSH Key:

```
$ asignify generate -s sshkey privkey
$ asignify generate --no-password -s sshkey privkey
```

- Sign Files

```
$ asignify sign secretkey digests.sig file1 file2 ...
```

- Verify a Digest File's Signature 

```
$ asignify verify publickey digests.sig
```

- Check the Integrity of Files Correspoinding to the Digests

```
$ asignify check publickey digests.sig file1 file2 ...
```

- Check Integrity Using an SSH Key

```
$ asignify check sshpubkey digests.sig file1 file2 ...
```

- Encrypt a File Using Your Private Key and a Peer's Public Key:

```
$ asignify encrypt ownprivkey peerpubkey in out
```

- Decrypt a File Using a Peer's Private Key and Your Public Key:

```
$ asignify decrypt peerprivkey ownpubkey in out
$ asignify encrypt -d peerprivkey ownpubkey in out
```
 
## Cryptographic Basis

Asignify relies on the same primitives as the `signify` utility. However, for the native format,
asignify uses the `blake2` cryptographic hash function instead of `sha512`. I decided this
mainly because of the performance of `blake2`. Since this function was in the final of
SHA3 competition (along with the current `keccak` winner), I believe that it is secure
enough for use as a collision-resistant hash function. Moreover, unlike sha2, blake2 is 
not vulnerable to extension attacks.

For digital signatures, `asignify` uses the `ed25519` algorithm which is blazingly fast and
proven to be secure even without a random oracle (based on Schnorr scheme). The `tweetnacl` library
is very small and precisely analyzed.

To sign a file, `asignify` does the following steps:

1. Calculates the digest of a file (e.g. `blake2` or `sha512`)
2. Opens the secret key file (decrypting it if needed)
3. Write all the digests to the output buffer in format:

```
SHA256 (filename) = deadbeef....
SIZE (filename) = 666
...
```

4. Calculates the ed25519 signature over using secret key and the following fields:
	- version
	- data
5. Afterwards, a signature is packed into the `asignify` signature line and prepended
to the digests content

To verify a signature, `asignify` loads the public key, verifies the signature in the same
way, loads the files' digest(s) and verifies the corresponding files agains those digests.

Hence, `asignify` only signs digests of files and not files themselves, and a signature
contains both digests and its ed25519 signature.

## Key Storage

The secret key for `asignify` can be encrypted using a password-based key derivation function,
namely `pbkdf2-blake2`. This function can be tuned for the number of rounds to increase
amount of work required for an adversary to brute force the encryption password into
a valid encryption key.

Currently, `asignify` uses the following fields for private keys:

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

The checksum is used to validate the password against the original encryption key. The current
minimum rounds count is 10000. However, it can be changed in future.

Public keys and signatures have nearly the same format:

~~~
magic:version:<b64_key_id>:<b64_key_data>
asignify-pubkey:1:kEjp3MrX5fE=:Hut...bl/mQ=
asignify-sig:1:kEjp3MrX5fE=:Sfg...A==
~~~

The key ID is used to match keypairs and the corresponding signatures.

## Libasignify API

`libasignify` provides a high-level API for the most common signature operations.

To verify a signature, you should do the following:

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

To sign files, you should provide a callback for the password prompt (e.g. by BSD function
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

Generation of keypairs is served by `libasignify` as well:

~~~C
if (!asignify_generate(seckeyfile, pubkeyfile, 1, rounds,
		read_password_verify, NULL)) {
	errx(1, "Cannot generate keypair");
}
~~~

Specifying `NULL` as a password callback leads to unencrypted secret keys being produced.


## Supported Digest Formats

- SHA256
- SHA512
- BLAKE2b

For sha2, `libasignify` can use openssl if it is available in the system since it
provides highly optimized versions of SHA that calculates checksums much quicker
than the sha2 code embedded into `libasignify`.

## OpenBSD Signatures

`libasignify` automatically recognises and parses OpenBSD signatures and public keys, allowing
verification of signatures produced by the `signify` utility transparently. Secret keys and signing
are currently unsupported, however support is planned in the future.

## Roadmap

- Better OpenBSD compatibility
- ~~Better CLI~~
- ~~Manpages and other docs~~
- Fuzz testing
- ~~Encryption via ed25519 <-> curve25519 transform~~

## License and Authors

This code is licensed under simplified BSD license and includes portions of third
party code designed and written by various authors:

- blake2: 
	+ Jean-Philippe Aumasson
	+ Christian Winnerlein
	+ Samuel Neves
	+ Zooko Wilcox-O'Hearn
- chacha20                               
	+ Daniel J. Bernstein
- salsa20
	+ Daniel J. Bernstein
- curve25519
	+ Daniel J. Bernstein
- curve25519xsalsa20poly1305
	+ Daniel J. Bernstein
- ed25519
	+ Daniel J. Bernstein
	+ Bo-Yin Yang
	+ Niels Duif
	+ Peter Schwabe
	+ Tanja Lange
- chacha20 implementation
	+ Andrew "floodyberry" Moon.
