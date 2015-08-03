(ns naclj.key-ed25519
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
	  (jnr.ffi.byref.LongLongByReference)
	  (java.net.URI)
    )
	(:require 
	  [naclj.key-protocol :refer :all]
	  [naclj.encode-util :refer :all]
	  [naclj.fixture :as f]
	  [clojure.tools.namespace.repl :refer [refresh]]
	  [clojure.java.io :refer [reader writer]]
	  ))

;; sodium constants
(def ed25519-bytes (.crypto_sign_ed25519_bytes (NaCl/sodium))) ; signature size
(def ed25519-seedbytes (.crypto_sign_ed25519_seedbytes (NaCl/sodium)))
(def ed25519-publickeybytes (.crypto_sign_ed25519_publickeybytes (NaCl/sodium)))
(def ed25519-secretkeybytes (.crypto_sign_ed25519_secretkeybytes (NaCl/sodium)))

;;;

(defrecord TEd25519KeyPair [private-key public-key])

(defrecord TEd25519PrivateKey [private-key-bs])

(defrecord TEd25519PublicKey [public-key-bs])

;;;

(defmethod make-key-pair [:sodium :ed25519]
  ;; make key-pair from either a private-key object, a private-key-bs byte-array,
  ;; or from scratch.
  ;; A TEd25519KeyPair is returned.
  [provider function & {:keys [kid private-key seed] :as xs}]
  (if (byte-array? private-key)
    (make-key-pair :sodium :curve25519 (->TEd25519PrivateKey private-key))
    (if (nil? private-key)
      ;; create a new key-pair from scratch
      (let [sk (byte-array ed25519-secretkeybytes)
            pk (byte-array ed25519-publickeybytes)]
        (.crypto_sign_ed25519_keypair
          (NaCl/sodium)
          pk
          sk)
        (->TEd25519KeyPair (->TEd25519PrivateKey sk) (->TEd25519PublicKey pk)))
      (if (private-key? private-key)
        (key-pair private-key)
        nil))))

;;;

(extend-type TEd25519KeyPair
  IKeyPair
    (key-pair [this] this)
    (private-key [this] (:private-key this))
    (public-key [this] (:public-key this))
  IKeyInfo
    (algorithm [this] "ed25519")
  IEqual
    (equal? [this that] 
    (if (satisfies? IKeyPair that)
       (or (= this that) 
           (equal? (private-key this) (private-key that)))
       false))
  )

(extend-type TEd25519PrivateKey
  IKey
    (pair? [this that]
      (and (public-key? that)
           (equal? (public-key this) that)))
  IKeyInfo
    (key-length [this] (count (=>bytes! this)))
    (algorithm [this] "ed25519")
  IKeyPair
    (key-pair [this] 
      (let [pk (byte-array ed25519-publickeybytes)]
        (.crypto_sign_ed25519_sk_to_pk 
          (NaCl/sodium) 
          pk 
          (=>bytes! (private-key this)))
        (->TEd25519KeyPair this (->TEd25519PublicKey pk))))
    (private-key [this] this)
    (public-key [this] (public-key (key-pair this)))
  IEqual
    (equal? [this that] 
      (if (satisfies? IKeyPair that)
         (or (= this that) 
             (equal? (=>bytes! this) (=>bytes! that)))
         false))
  IHexEncode
    (=>hex [this] (=>hex (:private-key-bs this)))
    (=>hex-str [this] (=>hex-str (:private-key-bs this)))
  Ibase64urlEncode
    (=>base64url [this] (=>base64url (:private-key-bs this)))
    (=>base64url-str [this] (=>base64url-str (:private-key-bs this)))
  IBytesEncode
  (=>bytes [this] (=>bytes (:private-key-bs this)))
  (=>bytes! [this] (=>bytes! (:private-key-bs this)))
  )

(extend-type TEd25519PublicKey
  IKey
    (pair? [this that]
      (and (private-key? that)
           (equal? this (public-key that))))
  IEqual
    (equal? [this that] (equal? (=>bytes! this) (=>bytes! that)))
  IKeyInfo
    (key-length [this] (count (=>bytes! this)))
    (algorithm [this] "ed25519")
  IHexEncode
    (=>hex [this] (=>hex (:public-key-bs this)))
    (=>hex-str [this] (=>hex-str (:public-key-bs this)))
  Ibase64urlEncode
    (=>base64url [this] (=>base64url (:public-key-bs this)))
    (=>base64url-str [this] (=>base64url-str (:public-key-bs this)))
  IBytesEncode
  (=>bytes [this] (=>bytes (:public-key-bs this)))
  (=>bytes! [this] (=>bytes! (:public-key-bs this)))
  IUriIdentify
    (uri [this]
      (java.net.URI. (str "urn:public-key:ed25519:base64url:" (=>base64url-str (=>bytes this)))))
  )


(defmethod key-pair? TEd25519KeyPair [o] true)
(defmethod private-key? TEd25519PrivateKey [o] true)
(defmethod public-key? TEd25519PublicKey [o] true)

