# Deprecated Effort

Please look at ""lvh/caesium" for alternative clojure-nacl/libsodium bindings.

# naclj

Clojure library that abstracts libsodium's NaCl primitives (curve25519, ed25519, blake2b, box/unbox, sign/verify, etc.)

## Usage

Still under construction... please check back later...

## Installation

Requires the C-library libsodium to be installed.
On Mac the easiest way to install is probably through brew:

    brew install libsodium



## History

I was looking for a Clojure library to work with NaCl's primitives. First I found the Clojure library Caesium, which is layered on top of Kalium, which is a Java library layered on top of libsodium.
Unfortunately, the development on Caesium seem to have stalled. Then I tried to enhance Caesium, but the underlying Kalium forces you too much in a non-functional, Java-like programming style. Got distracted by the TweetNacl effort in Java - would like to focus on that again once this naclj is stable. Lastly, I used the foreign function interface jnr-ffi definitions from Kalium directly, and started to extend the interfaces defined for libsodium. The end result doesn't use anything from Caesium and Kalium anymore, except for a single java-file that defines the jnr-ffi "glue" between  naclj's Clojure and libsodium's C-library.

## References

* NaCl (Dan Bernstein's "NaCl: Networking and Cryptography library")
  * http://nacl.cr.yp.to/
* libsodium (Frank Denis' fantastic C-implementation of Bernstein's NaCl)
  * https://download.libsodium.org/doc/
  * https://github.com/jedisct1/libsodium
* Kalium (Bruno Oliveira's comprehensive Java binding to the Networking and Cryptography (NaCl) library with the awesomeness of libsodium)
  * https://github.com/abstractj/kalium
* Caesium (lvh's Clojure bindings to Kalium's Java interfaces and implementation - unfortunately stalled after great start...)
  * https://github.com/lvh/caesium
* TweetNacl in Java (Tom Zhou amazing effort to have most of the NaCl functionality in a single pure java file.)
  * https://github.com/InstantWebP2P/tweetnacl-java
* jnr-ffi (cool foreign function interface to make it easier to call c-functions from Java... or Clojure)
  * https://com.github.jnr/jnr-ffi
        
        
## License

Copyright © 2015 Frank Siebenlist.

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
