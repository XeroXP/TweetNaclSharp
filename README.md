TweetNaclSharp
============

![](https://img.shields.io/nuget/v/TweetNaclSharp)
![](https://img.shields.io/nuget/dt/TweetNaclSharp?color=laim)
![](https://img.shields.io/appveyor/build/XeroXP/tweetnaclsharp/master)
![](https://img.shields.io/appveyor/tests/XeroXP/tweetnaclsharp/master)

Port of [TweetNaCl](http://tweetnacl.cr.yp.to) / [NaCl](http://nacl.cr.yp.to/)
to C#. Public domain.


Documentation
=============

* [Overview](#overview)
* [Audits](#audits)
* [Installation](#installation)
* [Examples](#examples)
* [Usage](#usage)
  * [Public-key authenticated encryption (box)](#public-key-authenticated-encryption-box)
  * [Secret-key authenticated encryption (secretbox)](#secret-key-authenticated-encryption-secretbox)
  * [Scalar multiplication](#scalar-multiplication)
  * [Signatures](#signatures)
  * [Hashing](#hashing)
  * [Random bytes generation](#random-bytes-generation)
  * [Constant-time comparison](#constant-time-comparison)
* [System requirements](#system-requirements)
* [Development and testing](#development-and-testing)
* [Benchmarks](#benchmarks)
* [Contributors](#contributors)
* [Who uses it](#who-uses-it)


Overview
--------

The primary goal of this project is to produce a translation of TweetNaCl to
C# which is as close as possible to the original C implementation, plus
a thin layer of idiomatic high-level API on top of it.

There are two versions, you can use either of them:

* `TweetNaclSharp.Nacl` is the port of TweetNaCl with minimum differences from the
  original + high-level API.

* `TweetNaclSharp.NaclFast` is like `TweetNaclSharp.Nacl`, but with some functions replaced with
  faster versions.


Installation
------------

You can install TweetNaclSharp via a package manager:

[NuGet](https://www.nuget.org/):

    $ Install-Package TweetNaclSharp

or [download source code](../../releases).


Examples
--------
You can find usage examples in our [wiki](../../wiki/Examples).


Usage
-----

All API functions accept and return bytes as `byte[]`s.  If you need to
encode or decode strings, use functions from
`TweetNacl.NaclUtil` or one of the more robust codec
packages.


### Public-key authenticated encryption (box)

Implements *x25519-xsalsa20-poly1305*.

#### TweetNaclSharp.Nacl.BoxKeyPair()

Generates a new random key pair for box and returns it as an object with
`PublicKey` and `SecretKey` members:

    {
       PublicKey: ...,  // byte[] with 32-byte public key
       SecretKey: ...   // byte[] with 32-byte secret key
    }


#### TweetNaclSharp.Nacl.BoxKeyPairFromSecretKey(secretKey)

Returns a key pair for box with public key corresponding to the given secret
key.

#### TweetNaclSharp.Nacl.Box(message, nonce, theirPublicKey, mySecretKey)

Encrypts and authenticates message using peer's public key, our secret key, and
the given nonce, which must be unique for each distinct message for a key pair.

Returns an encrypted and authenticated message, which is
`TweetNaclSharp.Nacl.BoxOverheadLength` longer than the original message.

#### TweetNaclSharp.Nacl.BoxOpen(box, nonce, theirPublicKey, mySecretKey)

Authenticates and decrypts the given box with peer's public key, our secret
key, and the given nonce.

Returns the original message, or `null` if authentication fails.

#### TweetNaclSharp.Nacl.BoxBefore(theirPublicKey, mySecretKey)

Returns a precomputed shared key which can be used in `TweetNaclSharp.Nacl.BoxAfter` and
`TweetNaclSharp.Nacl.BoxOpenAfter`.

#### TweetNaclSharp.Nacl.BoxAfter(message, nonce, sharedKey)

Same as `TweetNaclSharp.Nacl.Box`, but uses a shared key precomputed with `TweetNaclSharp.Nacl.BoxBefore`.

#### TweetNaclSharp.Nacl.BoxOpenAfter(box, nonce, sharedKey)

Same as `TweetNaclSharp.Nacl.BoxOpen`, but uses a shared key precomputed with `TweetNaclSharp.Nacl.BoxBefore`.

#### Constants

##### TweetNaclSharp.Nacl.BoxPublicKeyLength = 32

Length of public key in bytes.

##### TweetNaclSharp.Nacl.BoxSecretKeyLength = 32

Length of secret key in bytes.

##### TweetNaclSharp.Nacl.BoxSharedKeyLength = 32

Length of precomputed shared key in bytes.

##### TweetNaclSharp.Nacl.BoxNonceLength = 24

Length of nonce in bytes.

##### TweetNaclSharp.Nacl.BoxOverheadLength = 16

Length of overhead added to box compared to original message.


### Secret-key authenticated encryption (secretbox)

Implements *xsalsa20-poly1305*.

#### TweetNaclSharp.Nacl.Secretbox(message, nonce, key)

Encrypts and authenticates message using the key and the nonce. The nonce must
be unique for each distinct message for this key.

Returns an encrypted and authenticated message, which is
`TweetNaclSharp.Nacl.SecretboxOverheadLength` longer than the original message.

#### TweetNaclSharp.Nacl.SecretboxOpen(box, nonce, key)

Authenticates and decrypts the given secret box using the key and the nonce.

Returns the original message, or `null` if authentication fails.

#### Constants

##### TweetNaclSharp.Nacl.SecretboxKeyLength = 32

Length of key in bytes.

##### TweetNaclSharp.Nacl.SecretboxNonceLength = 24

Length of nonce in bytes.

##### TweetNaclSharp.Nacl.SecretboxOverheadLength = 16

Length of overhead added to secret box compared to original message.


### Scalar multiplication

Implements *x25519*.

#### TweetNaclSharp.Nacl.ScalarMult(n, p)

Multiplies an integer `n` by a group element `p` and returns the resulting
group element.

#### TweetNaclSharp.Nacl.ScalarMultBase(n)

Multiplies an integer `n` by a standard group element and returns the resulting
group element.

#### Constants

##### TweetNaclSharp.Nacl.ScalarMultScalarLength = 32

Length of scalar in bytes.

##### TweetNaclSharp.Nacl.ScalarMultGroupElementLength = 32

Length of group element in bytes.


### Signatures

Implements [ed25519](http://ed25519.cr.yp.to).

#### TweetNaclSharp.Nacl.SignKeyPair()

Generates new random key pair for signing and returns it as an object with
`PublicKey` and `SecretKey` members:

    {
       PublicKey: ...,  // byte[] with 32-byte public key
       SecretKey: ...   // byte[] with 64-byte secret key
    }

#### TweetNaclSharp.Nacl.SignKeyPairFromSecretKey(secretKey)

Returns a signing key pair with public key corresponding to the given
64-byte secret key. The secret key must have been generated by
`TweetNaclSharp.Nacl.SignKeyPair` or `TweetNaclSharp.Nacl.SignKeyPairFromSeed`.

#### TweetNaclSharp.Nacl.SignKeyPairFromSeed(seed)

Returns a new signing key pair generated deterministically from a 32-byte seed.
The seed must contain enough entropy to be secure. This method is not
recommended for general use: instead, use `TweetNaclSharp.Nacl.SignKeyPair` to generate a new
key pair from a random seed.

#### TweetNaclSharp.Nacl.Sign(message, secretKey)

Signs the message using the secret key and returns a signed message.

#### TweetNaclSharp.Nacl.SignOpen(signedMessage, publicKey)

Verifies the signed message and returns the message without signature.

Returns `null` if verification failed.

#### TweetNaclSharp.Nacl.SignDetached(message, secretKey)

Signs the message using the secret key and returns a signature.

#### TweetNaclSharp.Nacl.SignDetachedVerify(message, signature, publicKey)

Verifies the signature for the message and returns `true` if verification
succeeded or `false` if it failed.

#### Constants

##### TweetNaclSharp.Nacl.SignPublicKeyLength = 32

Length of signing public key in bytes.

##### TweetNaclSharp.Nacl.SignSecretKeyLength = 64

Length of signing secret key in bytes.

##### TweetNaclSharp.Nacl.SignSeedLength = 32

Length of seed for `TweetNaclSharp.Nacl.SignKeyPairFromSeed` in bytes.

##### TweetNaclSharp.Nacl.SignSignatureLength = 64

Length of signature in bytes.


### Hashing

Implements *SHA-512*.

#### TweetNaclSharp.Nacl.Hash(message)

Returns SHA-512 hash of the message.

#### Constants

##### TweetNaclSharp.Nacl.HashHashLength = 64

Length of hash in bytes.


### Random bytes generation

#### TweetNaclSharp.Nacl.RandomBytes(length)

Returns a `byte[]` of the given length containing random bytes of
cryptographic quality.

**Implementation note**

TweetNaclSharp uses the following methods to generate random bytes,
it runs on:

* `System.Security.Cryptography.RandomNumberGenerator` (standard)


### Constant-time comparison

#### TweetNaclSharp.Nacl.Verify(x, y)

Compares `x` and `y` in constant time and returns `true` if their lengths are
non-zero and equal, and their contents are equal.

Returns `false` if either of the arguments has zero length, or arguments have
different lengths, or their contents differ.


System requirements
-------------------

TweetNaclSharp supports:

* Net 6
