(ns naclj.key-protocol
  (:require [naclj.encode-util :refer :all]
            [naclj.hash-protocol :as hp]
            [naclj.hash-blake2b])
	(:import 
	  (java.util.Random)
            ))

;;

(defprotocol IKey
  "Describes the functionality of a key."
  (->pem! [this file-path])
  (encoded [this])
  (encoding-format [this])
  (pair? [this that])
  (kid [this])
  )

(defprotocol IKeyPair
  "Describes the functionality of a keypair."
  (private-key [this])
  (public-key [this])
  (key-pair [this])
  )

(defprotocol ISigningKeyPair
  "Convenience functions that work with a key-pair dedicated to signing and verifying operations."
  (signing-key [this])
  (verifying-key [this])
  )

(defprotocol IEncryptionKeyPair
  "Convenience functions that work with a key-pair dedicated to encryption and decryption operations."
  (encryption-key [this])
  (decryption-key [this])
  )

(defprotocol IPrivateKey
  "Describes the functionality of a private key."
  )

(defprotocol IPublicKey
  "Describes the functionality of a public key."
  )

(defprotocol IDHKey
  "Interface that returns the derived Diffie-Hellman symmetric key from the pub and priv keys."
  (dh-key [this pub-priv-key])
  )

(defprotocol IPKeyEdToCurve25519
  "Interface that returns the derived Diffie-Hellman symmetric key from the pub and priv keys."
  (curve25519-public-key [this]))

(defprotocol ISKeyEdToCurve25519
  "Interface that returns the derived Diffie-Hellman symmetric key from the pub and priv keys."
  (curve25519-private-key [this]))

(defprotocol IKeyInfo
  "Provide some key properties."
  (key-length [this])
  (algorithm [this])
  )

;;

(defmulti make-key-pair
  (fn [provider function & xs] [provider function]))

;;;

(defmulti key-pair? type)
(defmulti private-key? type)
(defmulti public-key? type)
(defmulti signing-key? type)
(defmulti verifying-key? type)
(defmulti decryption-key? type)
(defmulti encryption-key? type)
(defmulti dh-public-key? type)
(defmulti dh-private-key? type)

(defmethod key-pair? :default [o] false)
(defmethod private-key? :default [o] false)
(defmethod public-key? :default [o] false)
(defmethod signing-key? :default [o] false)
(defmethod verifying-key? :default [o] false)
(defmethod decryption-key? :default [o] false)
(defmethod encryption-key? :default [o] false)
(defmethod dh-public-key? :default [o] false)
(defmethod dh-private-key? :default [o] false)

;;;

(defprotocol IRandomGenerator
  "Interface that returns arrays of random numbers."
  (random-bytes [this size])
  (random-bytes! [this bs]))

(defmulti make-random-generator
  "Random number generator factory that returns a generator for a certain provider"
  (fn [provider & xs] provider))

;

(defrecord TRandomGeneratorJava [random-generator])

(defmethod make-random-generator :java.util.Random [provider] 
  (map->TRandomGeneratorJava {:random-generator (java.util.Random.)}))

(extend-type TRandomGeneratorJava
  IRandomGenerator
    (random-bytes [this size] 
      (let [bs (byte-array size)]
        (.nextBytes (:random-generator this) bs)
        bs))
    (random-bytes! [this bs] 
      (.nextBytes (:random-generator this) bs)
      bs))

;;;

(defrecord TGenericKey [key-bs provider])

(defmulti make-key
  (fn [provider function & xs] [provider function]))

(defmethod make-key :default
  [provider function & {:keys [size] :as xs}]
  (map->TGenericKey :key-bs (random-bytes (make-random-generator :java.util.Random) size)
                    :provider :sodium))

;;;

(extend-type TGenericKey
  IKey
    (pair? [this that] false)
  IEqual
    (equal? [this that] (equal? (=>bytes this) (=>bytes that)))
  IKeyInfo
    (key-length [this] (count (:key-bs this)))
  IHexEncode
    (=>hex [this] (=>hex (:key-bs this)))
    (=>hex-str [this] (=>hex-str (:key-bs this)))
  Ibase64urlEncode
    (=>base64url [this] (=>base64url (:key-bs this)))
    (=>base64url-str [this] (=>base64url-str (:key-bs this)))
  IBytesEncode
  (=>bytes [this] (aclone (:key-bs this)))
  )

(defn key-hash-id
  "In order to obtain an intrinsic identifier/name for a key/secret-key/private-key,
  we return the hash of that byte-array of that secret.
  To add an additional layer of security, we use a key'ed hashing algorithm where the hashing-key
  is the secret itself. 
  In order to obtain a hashing-key of the correct size, we actually hash the secret one time
  with a hash-size of the desired key-size for the subsequent key'ed hashing step. The result
  of the latter is returned as a byte-array of 32 bytes.
  The resulting byte-array hash value will be a univerally unique identifier for the secret, which
  does not leak any data from the secret itself.
  For easier consumption, the returned byte-array can be converted to hex or base64(url)."
  [bs]
  (let [bs (=>bytes bs)
        ;; first hash the key byte-array to obtain a key-length we can use for the hashing-key
        h (hp/digest (hp/make-message-digester :sodium :blake2b) bs)
        ;; then use the hash value as the hashing-key to hash the original key
		kh (hp/digest (hp/make-message-digester :sodium :blake2b :key (=>bytes h)) bs)]
	;; return the resulting byte-array as the identifier to use.
    (=>bytes kh)))
;;;
