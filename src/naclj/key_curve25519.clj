(ns naclj.key-curve25519
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
    )
	(:require 
	  [naclj.key-protocol :refer :all]
    [naclj.uri-util :refer :all]
	  [naclj.encode-util :refer :all]
	  [naclj.fixture :as f]
	  [clojure.java.io :refer [reader writer]]
	  ))

;; sodium constants
(def curve25519-seedbytes (.crypto_box_curve25519xsalsa20poly1305_seedbytes (NaCl/sodium)))
(def curve25519-publickeybytes (.crypto_box_curve25519xsalsa20poly1305_publickeybytes (NaCl/sodium)))
(def curve25519-secretkeybytes (.crypto_box_curve25519xsalsa20poly1305_secretkeybytes (NaCl/sodium)))
(def curve25519-beforenmbytes (.crypto_box_curve25519xsalsa20poly1305_beforenmbytes (NaCl/sodium)))
(def noncebytes (.crypto_box_curve25519xsalsa20poly1305_noncebytes (NaCl/sodium)))
(def zerobytes (.crypto_box_curve25519xsalsa20poly1305_zerobytes (NaCl/sodium)))
(def boxzerobytes (.crypto_box_curve25519xsalsa20poly1305_boxzerobytes (NaCl/sodium)))
(def macbytes (.crypto_box_curve25519xsalsa20poly1305_macbytes (NaCl/sodium)))

;;;

(defrecord TSodiumBoxed [cypher-text nonce])

(defrecord TCurve25519KeyPair [private-key public-key])

(defrecord TCurve25519PrivateKey [private-key-bs])

(defrecord TCurve25519PublicKey [public-key-bs])

(defrecord TCurve25519DHKey [key-bs])

;;;

(defmethod make-key-pair [:sodium :curve25519]
  ;; make key-pair from either a private-key object, a private-key-bs byte-array,
  ;; or from scratch.
  ;; A TCurve25519KeyPair is returned.
  [provider function & {:keys [kid private-key] :as xs}]
  (if (byte-array? private-key)
    (make-key-pair :sodium :curve25519 (->TCurve25519PrivateKey private-key))
    (if (nil? private-key)
      ;; create a new key-pair from scratch
      (let [sk (byte-array curve25519-secretkeybytes)
            pk (byte-array curve25519-publickeybytes)]
        (.crypto_box_curve25519xsalsa20poly1305_keypair
          (NaCl/sodium)
          pk
          sk)
        (->TCurve25519KeyPair (->TCurve25519PrivateKey sk) (->TCurve25519PublicKey pk)))
      (if (private-key? private-key)
        (key-pair private-key)
        nil))))



(defmethod make-key [:sodium :curve25519]
  [provider function & {:keys [key-pair private-key public-key] :as xs}]
  (assert (and (or key-pair private-key) public-key)
    "In order to generate the curve25519 DH key, we need one public-key, and a key-pair or private-key")
  (dh-key public-key (or private-key key-pair)))

;;;

(extend-type TCurve25519KeyPair
  IKeyPair
    (key-pair [this] this)
    (private-key [this] (:private-key this))
    (public-key [this] (:public-key this))
  IDHKey
    (dh-key [this a-public-key]
      (dh-key (private-key this) a-public-key))
  IKeyInfo
    (algorithm [this] "curve25519")
  IEqual
    (equal? [this that] 
    (if (satisfies? IKeyPair that)
       (or (= this that) 
           (equal? (private-key this) (private-key that)))
       false))
  IUriIdentify
    (uri [this]
      (java.net.URI. (str "urn:nacl:kp:curve25519:" (=>base64url-str (public-key this)))))
  )

(extend-type TCurve25519PrivateKey
  IKey
    (pair? [this that]
      (and (public-key? that)
           (equal? (public-key this) that)))
  IKeyInfo
    (key-length [this] (count (=>bytes! this)))
    (algorithm [this] "curve25519")
  IKeyPair
    (key-pair [this] 
      (let [pk (byte-array curve25519-publickeybytes)]
        (.crypto_scalarmult_curve25519_base 
          (NaCl/sodium) 
          pk 
          (=>bytes! (private-key this)))
        (->TCurve25519KeyPair this (->TCurve25519PublicKey pk))))
    (private-key [this] this)
    (public-key [this] (public-key (key-pair this)))
  IDHKey
    (dh-key [this a-public-key]
      (assert (public-key? a-public-key) 
        "DH Key derivation - Second key is no public key.")
      (assert (= (algorithm this) (algorithm a-public-key)) 
        (str "DH Key derivation - Keys are not both of the same type: " 
             (algorithm this) " vs " (algorithm a-public-key)))
      (let [k-bs (byte-array curve25519-beforenmbytes)
            ;; use the xor of the 2 public keys as the identifier for the dh-key
            dh-id-xor (byte-array (map bit-xor (=>bytes! a-public-key) 
                                               (=>bytes! (public-key this))))
            ret (.crypto_box_curve25519xsalsa20poly1305_beforenm 
                  (NaCl/sodium) 
                  k-bs
                  (=>bytes! a-public-key)
                  (=>bytes! this))]
        (if (= ret 0)
          (assoc (->TCurve25519DHKey k-bs) :public-key-A (public-key this) 
                                           :public-key-B a-public-key
                                           :id-xor dh-id-xor)
          nil)))
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
  IUriIdentify
    (uri [this]
      (java.net.URI. (str "urn:nacl:sk:curve25519:" (=>base64url-str (public-key this)))))
  )

(extend-type TCurve25519PublicKey
  IKey
    (pair? [this that]
      (and (private-key? that)
           (equal? this (public-key that))))
  IDHKey
    (dh-key [this a-private-key]
      (assert (private-key? a-private-key) 
              "DH Key derivation - Second key is no private key.")
      (assert (= (algorithm this) (algorithm a-private-key)) 
              (str "DH Key derivation - Keys are not both of the same type: " 
                   (algorithm this) " vs " (algorithm a-private-key)))
      (dh-key a-private-key this))
  IEqual
    (equal? [this that] (equal? (=>bytes! this) (=>bytes! that)))
  IKeyInfo
    (key-length [this] curve25519-publickeybytes)
    (algorithm [this] "curve25519")
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
      (java.net.URI. (str "urn:nacl:pk:curve25519:" (=>base64url-str this))))
  )

(extend-type TCurve25519DHKey
  IKey
    (pair? [this that] false)
  IEqual
    (equal? [this that] (equal? (=>bytes! this) (=>bytes! that)))
  IKeyInfo
    (key-length [this] (count (:key-bs this)))
    (algorithm [this] "curve25519-dh")
  IHexEncode
    (=>hex [this] (=>hex (:key-bs this)))
    (=>hex-str [this] (=>hex-str (:key-bs this)))
  Ibase64urlEncode
    (=>base64url [this] (=>base64url (:key-bs this)))
    (=>base64url-str [this] (=>base64url-str (:key-bs this)))
  IBytesEncode
  (=>bytes ([this] (=>bytes (:key-bs this))))
  (=>bytes! ([this] (=>bytes! (:key-bs this))))
  IUriIdentify
    (uri [this]
      (java.net.URI. (str "urn:nacl:dh-key:curve25519-xor:" 
                          (=>base64url-str (=>bytes (:id-xor this))))))
  )


(defmethod key-pair? TCurve25519KeyPair [o] true)
(defmethod private-key? TCurve25519PrivateKey [o] true)
(defmethod public-key? TCurve25519PublicKey [o] true)
(defmethod dh-public-key? TCurve25519PublicKey [o] true)
(defmethod dh-private-key? TCurve25519PrivateKey [o] true)

(defn box-curve25519xsalsa20poly1305 
  ([sk pk msg] (box-curve25519xsalsa20poly1305 sk pk msg nil))
  ([sk pk msg nonce]
    (assert (private-key? sk))
    (assert (public-key? pk))
    (let [sk-bs (=>bytes! sk)
          pk-bs (=>bytes! pk)
          nonce-bs (if nonce (=>bytes! nonce) (make-random-bytes noncebytes))
          ;; prepend ZERO_BYTES to msg-buffer
          msg0 (byte-array (mapcat seq [(byte-array zerobytes) msg]))
          ct (byte-array (count msg0))
          ret (.crypto_box_curve25519xsalsa20poly1305
                (NaCl/sodium)
                ct
                msg0
                (count msg0)
                nonce-bs
                pk-bs
                sk-bs)]
      (if (= ret 0)
          ;; drop BOXZERO_BYTES from cyphertext buffer
          (let [ct0 (byte-array (drop boxzerobytes ct))]
            (map->TSodiumBoxed {:cypher-text ct0 :nonce nonce-bs 
                                :public-key-A pk :public-key-B (public-key sk)}))
          {:ret ret}))))

                
(defn box-open-curve25519xsalsa20poly1305 
  ([sk a-boxed]
    (let [ct (:cypher-text a-boxed)
          nonce-bs (=>bytes! (:nonce a-boxed))
          pk (if (pair? sk (:public-key-A a-boxed)) 
               (:public-key-B a-boxed) 
               (:public-key-A a-boxed))]
      (box-open-curve25519xsalsa20poly1305 sk pk nonce-bs ct)))
  ([sk pk nonce-bs ct]
    (assert (private-key? sk))
    (assert (public-key? pk))
    (let [sk-bs (=>bytes! sk)
          pk-bs (=>bytes! pk)
          ;; prepend BOXZERO_BYTES to cyphertext
          ct0 (byte-array (mapcat seq [(byte-array boxzerobytes) ct]))
          msg0-bs (byte-array (count ct0))
          ret (.crypto_box_curve25519xsalsa20poly1305_open
                (NaCl/sodium)
                msg0-bs
                ct0
                (count msg0-bs)
                nonce-bs
                pk-bs
                sk-bs)]
        (if (= ret 0)
          ;; drop ZERO_BYTES from decrypted msg-buffer
          (let [msg-bs (byte-array (drop zerobytes msg0-bs))]
            {:msg msg-bs :public-key-sender pk})
          {:ret ret}))))




(comment 
(require '[naclj.key-curve25519 :as c])
(require '[naclj.key-protocol :as p])
(def kp-alice (p/make-key-pair :sodium :curve25519))
(def kp-bob (p/make-key-pair :sodium :curve25519))
(def sk-alice (p/private-key kp-alice))
(def sk-bob (p/private-key kp-bob))
(def pk-alice (p/public-key kp-alice))
(def pk-bob (p/public-key kp-bob))
(def ct-m (c/box-curve25519xsalsa20poly1305 sk-alice pk-bob (=>bytes "hello from Alice to Bob")))
ct-m
(def msg-m (c/box-open-curve25519xsalsa20poly1305 sk-bob pk-alice (:nonce ct-m) (:ct ct-m)))
msg-m
(=>string (:msg msg-m))
)

;cognitect.transit=> bs
;#<byte[] [B@136d7df7>
;cognitect.transit=> (vec bs)
;[1 0 127 0 0 0 0 0 0 0]
;cognitect.transit=> (vec (byte-array (mapcat seq [bs bs])))
;[1 0 127 0 0 0 0 0 0 0 1 0 127 0 0 0 0 0 0 0]
;cognitect.transit=> (vec (byte-array (apply concat [bs bss])))
;[1 0 127 0 0 0 0 0 0 0 1 0 127 0 0 0 0 0 0 0]
;cognitect.transit=> (vec (byte-array (drop 2 bs)))
;[127 0 0 0 0 0 0 0]
