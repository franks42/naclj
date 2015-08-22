(ns naclj.msg-box
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
    )
	(:require 
	  [naclj.key-protocol :refer :all]
	  [naclj.encode-util :refer :all]
	  [naclj.key-curve25519]
	  [naclj.fixture :as f]
	  [naclj.sodium-random]
	  [clojure.java.io :refer [reader writer]]
	  ))

(def rndm (make-random-generator :sodium))

(comment ;;; temporary...


;; sodium constants
(def noncebytes (.crypto_box_curve25519xsalsa20poly1305_noncebytes (NaCl/sodium)))
(def curve25519-beforenmbytes (.crypto_box_curve25519xsalsa20poly1305_beforenmbytes (NaCl/sodium)))

;;;

; Alice creates a MessageBoxUnBoxer with her private key(-pair) and Bob's public-key
; Alice can reuse this MessageBoxUnBoxer for any subsequent encrypted messages to send to Bob,
; or to decrypt and authenticate message that she receives from Bob.
(defrecord TMessageBoxUnBoxer [kp-A pk-B k-AB])

; Given a message, Alice's MessageBoxUnBoxer for bob yields a BoxedMessage
; with the cypher-test, the nonce used, and both Alice and Bob's public-key's
(defrecord TBoxedMessage [ct n pk-A pk-B])

; For the received BoxedMessage from Alice, Bob creates an MessageBoxUnboxer
; with given pk-B, Bob find the associated private-key, i.e. key-pair kp-B.
; and adds Alice's public-key pk-A
; Bob can reuse this MessageBoxUnBoxer to decrypt any subsequent encrypted message received from Alice,
; and Bob can reply to Alice by using the same MessageBobUnBoxer to encrypt messages for her.

; Given the cypher-text and the nonce, Bob's MessageUnboxer decrypts and verifies
; Alice's BoxedMessage, and yields an UnBoxedMessage with the decrypted message
; and an identifier for the sender, i.e. Alice's public-key or an identifier for the 
; shared key between Alice and Bob
(defrecord TUnBoxedMessage [msg pk-A k-AB-id])

;;;

(defprotocol IMessageBoxUnBoxer
  "Describes the functionality of a keypair."
  (box [this msg-bs][this msg-bs nonce]
  "Box (encrypt&sign) the provided message and return in a BoxedMessage structure")
  (open [this ct-bs nonce-bs]
  "Open (decrypt&verify) the cypher-text and return in a UnBoxedMessage structure")
  )


;;;



(defmethod make-message-boxunboxer [:sodium :curve25519xsalsa20poly1305]
  [provider function & {:keys [key-pair public-key receiver-id key-lookup-fn ] :as xs}]
  (->TMessageBoxUnBoxer ))

(defmethod make-message-boxunboxer [:sodium :xsalsa20poly1305]
  [provider function & {:keys [key-pair ] :as xs}]
  (->TMessageBoxUnBoxer ))

;;;

(extend-type TMessageBoxUnBoxer
  IMessageBoxUnBoxer
  (box 
    ([this msg] (box this msg-bs nonce))
    ([this msg nonce]
      (let [sk (private-key (:kp this))
            sk-bs (=>bytes sk)
            pk-bs (=>bytes (:pk this))
            msg-bs (=>bytes msg)
            nonce-bs (if nonce (=>bytes nonce) (random-bytes rndm noncebytes))
            ;; prepend ZERO_BYTES to msg-buffer
            msg0 (byte-array (mapcat seq [(byte-array zerobytes) msg-bs]))
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
              (map->TMessageBoxed {:ct ct0 :n nonce-bs 
                                  :pk-A (:pk this) :pk-B (public-key sk)}))
            {:ret ret})))

  ))

;;;

(defrecord TXsalsa20Poly1305Key [key-bs])

(defmethod make-key [:sodium :xsalsa20poly1305]
  [provider function & {:keys [] :as xs}]
  (map->TXsalsa20Poly1305Key :key-bs (random-bytes rndm curve25519-beforenmbytes)
                             :function :xsalsa20poly1305
                             :provider :sodium))

;;;

(defn box-curve25519xsalsa20poly1305 
  ([sk pk msg] (box-curve25519xsalsa20poly1305 sk pk msg nil))
  ([sk pk msg nonce]
    (assert (private-key? sk))
    (assert (public-key? pk))
    (let [sk-bs (=>bytes sk)
          pk-bs (=>bytes pk)
          nonce-bs (if nonce (=>bytes nonce) (random-bytes rndm noncebytes))
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
          nonce-bs (=>bytes (:nonce a-boxed))
          pk (if (pair? sk (:public-key-A a-boxed)) 
               (:public-key-B a-boxed) 
               (:public-key-A a-boxed))]
      (box-open-curve25519xsalsa20poly1305 sk pk nonce-bs ct)))
  ([sk pk nonce-bs ct]
    (assert (private-key? sk))
    (assert (public-key? pk))
    (let [sk-bs (=>bytes sk)
          pk-bs (=>bytes pk)
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

) ;;; comment


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
