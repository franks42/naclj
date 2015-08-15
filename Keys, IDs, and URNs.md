# Keys, IDs, and URNs

Why naclj uses "intrinsic" key identifiers that are URNs.

## Keys and Signed & Private Messages

In order to exchange messages securely with another party, we have to use symmetric and/or public keys. On one end, Alice uses some keys to sign and encrypt messages, and on the receiving end, Bob verifies and decrypts Alice's messages with the proper set of associated keys.

Alice faces the challenge to find the right key to use to sign and encrypt the message for Bob, and Bob has the equivalent task to find the correct keys that will verify and decrypt those messages.

When public keys are used, the complete public keys or whole certificates are often sent with the message to facilitate the processing. This works for signed messages, but not for encrypted message and not for hmac-signed messages with symmetric keys.

Another way that the associated keys are found, is by sending some key-identifier ("kid") with the message, which Bob can use to find Alice's keys in its own key-db. The latter is a database where Bob maintains previously stored (and trusted) keys with their association to other parties.

Sometimes the keys are "somehow" associated with the context and depend on custom application code.

## key to kid to subject mappings

The way key-identifiers are often used, is to directly map a key to a key-holder, i.e. a subject.

The naclj library separates the concerns of finding the keys with the key-identifiers, from finding the subjects associated with those keys.

We have essentially two separate mapping tables: (kid, key) and (kid,subject).

The first table is all we need to encrypt, decrypt, sign and verify messages. 

The second table links to the application layer, and is concerned with the Alices and Bobs. Note that 



## Intrinsic Key Identifiers

Key identifiers come in many flavors, and not commonly standardized. Sometimes expressive strings are used, like "Bob's encryption key", or just randomly generated string or UUID.

The issue with those identifiers is that the association between kid and key is unique for each key, and that implies that that association has to be explicitly shared and maintained between the communicating parties for each key.

Intrinsic key identifiers are names that can be derived from the keys themselves through a standardized recipe or algorithm. If the parties agree on the identifier generation scheme, then each party can generate an identifier for a key that will be understood by any receiver.

### Public Keys

For example, using the hash (e.g. sha256) of a public key as an intrinsic identifier, allows all parties to index their key-db with the hashes of the public keys that they "know" about.

For NaCl's curve25519 and ed25519 elliptic curve keys, the public keys are represented by 32 bytes... thirty two bytes!!! ... that is unbelievably small!!! This small key size allows us to put the whole key into the key-identifier, and we end up with an "intrinsic" name for a public key that has the public key embedded in it.

### Private Keys

For the secret keys, like private, signing, decrypting, and symmetric keys, it is a little more tricky to find a similar intrinsic naming scheme, because we do not want to leak any information about the key value itself in the identifier. 

For the private key of a key pair, however, we can use the same identifier that we use for the associated public key. 

### Symmetric/Secret Keys

For symmetric keys, we have no public key equivalent that we can use as an identifier. However, we can use a one-way-function like a secure hash or an hmac authentication tag to generate a unique identifier for that key.

Note that it is assumed that the shared secret is some random sequence of bytes with enough entropy such that brute force attacks are not feasible and/or impractical.

#### HMAC-tag as key identifier.

If we hmac-sign a fixed, standardized string, like "My authN tag is the key's id", then the resulting authentication tag is unique for the combination of that string and the key that was used to produce the tag. If we all use the same string, then the associated tags are essentially identifiers for those keys.

Libsodium's crypto_auth() function returns a authentication mac/tag with a size of 32 bytes. 

#### Secure Hash value as key identifier

An alternative identifier for a secret key is the secure hash of that key (SHA256/512, Blake2b).

As long as the key is a random set of bits, the hash value will not leak any real information from the key. (low-entropy password/passphrase secrets need extra care - not dealt with here)

Even though there are no realistic attacks on this approach, it still makes some people feel a little uneasy... When we use libsodium's blake2b implementation, we can add an additional layer of security by using the password option while generating the hash. When we use the secret itself as the password that we use to generate the blake2b-hash, then we add additional complexity to any (brute force) attack. Hopefully this scheme will appease all.

## naclj's key identifiers

The naclj's key identifier conventions are:

* curve25519 and ed25519 public keys: the 32 bytes that represent the public key
* curve25519 and ed25519 private keys or key-pairs: the 32 bytes that represent the public key
* (symmetric) keys: the 32 byte hash value of a 32 byte password-based blake2b hashing - the 32 byte password is the 32 byte non-password-based blake2b hash of the secret key. The hashing of the secret is to ensure we have a 32 byte password from whatever size the secret may be.

## URNs


## naclj's urn namespace conventions

The naclj library uses urn's for the key-identifiers values.

* The namespace identifier will be "nacl".
* The namespace string is the base64url representation of the binary octet stream of the value.
* The sub-namespace names defines the type of object and the algoritms used to generate the namespace string value of the urn.

By parsing the urn, the (sub-)namespace names and their standardized meaning, should allow a relying party to generate canonical urn's for its collection of secrets.

The following urn schema are used:

* The urn for a public key will have a first sub-namespace name of "pk".
* The urn for a private key will have a first sub-namespace name of "sk".
* The urn for a private&public key-pair will have a first sub-namespace name of "kp".
* The urn for a public or private key or key-pair will have a second sub-namespace name of that designates the algorithm, like "curve25519" or "ed25519".
* The urn for a public key, private key and key-pair for the curve25519 and ed25519 ECs, will all have a namespace string with a value of the base64url encode bytes of the public key.

For example:

* URNs for curve25519 and ed25519 public, private keys and key-pairs:
  * "urn:nacl:pk:curve25519:KSSPKKWRrSaZ5wL3PCDV1jE-31McqaBMq6Tbn_BQoCw"
  * "urn:nacl:sk:curve25519:KSSPKKWRrSaZ5wL3PCDV1jE-31McqaBMq6Tbn_BQoCw"
  * "urn:nacl:kp:curve25519:KSSPKKWRrSaZ5wL3PCDV1jE-31McqaBMq6Tbn_BQoCw"
  * "urn:nacl:pk:ed25519:3D5G6BsTe9GCJz0bm_Z5b_N8NTIpcb7tAeUv4MnBGIU"
  * "urn:nacl:sk:ed25519:3D5G6BsTe9GCJz0bm_Z5b_N8NTIpcb7tAeUv4MnBGIU"
  * "urn:nacl:kp:ed25519:3D5G6BsTe9GCJz0bm_Z5b_N8NTIpcb7tAeUv4MnBGIU"
* URN for generic secret/symmetric keys:
  * "urn:nacl:k:hash:blake2bp:V2jyhd8tX-19vpEhyrDzIHgUYyDA5MS1Qi71iw1SUP0"



The urn for a (symmetric) key will have a first sub-namespace name of "k".

## References

* NaCl (Dan Bernstein's "NaCl: Networking and Cryptography library")
  * http://nacl.cr.yp.to/
* libsodium (Frank Denis' fantastic C-implementation of Bernstein's NaCl)
  * https://download.libsodium.org/doc/
  * https://github.com/jedisct1/libsodium
        
