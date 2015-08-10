(ns naclj.signature-ed25519
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
	  (jnr.ffi.byref.LongLongByReference)
    [clojure.lang IFn]
    [clojure.lang.AFn]
    )
	(:require 
	  [naclj.key-ed25519]
	  [naclj.key-protocol :refer :all]
	  [naclj.encode-util :refer :all]
	  [naclj.fixture :as f]
	  [clojure.java.io :refer [reader writer]]
	  ))

;; sodium constants
(def ed25519-bytes (.crypto_sign_ed25519_bytes (NaCl/sodium))) ; signature size

;;;


;

; LongLongByReference ap = new LongLongByReference(0);
; lib.get_a(ap);
; System.out.printf("a from lib=%d\n", a.longValue());

;int crypto_sign_ed25519_detached(@Out byte[] sig,
;                                 @Out LongLongByReference siglen_p,
;                                 @In byte[] m,
;                                 @u_int64_t long mlen,
;                                 @In byte[] sk);
;
;int crypto_sign_ed25519_verify_detached(@In byte[] sig,
;                                        @In byte[] m,
;                                        @u_int64_t long mlen,
;                                        @In byte[] pk);

(defn sign-detached-ed25519 [msg, kp]
  (let [sig-bs (byte-array ed25519-bytes)
        siglen-ref (jnr.ffi.byref.LongLongByReference. 0)
        msg-bs (=>bytes msg)
        mlen (count msg-bs)
        sk-bs (=>bytes (private-key kp))
        ret (.crypto_sign_ed25519_detached
              (NaCl/sodium)
              sig-bs siglen-ref
              msg-bs mlen
              sk-bs)]
    (if (= ret 0)
      {:msg msg-bs :sig sig-bs :sig-len (.longValue siglen-ref) :alg "ed25519" :signer (public-key kp)}
      {:ret ret})))


(defn verify-detached-ed25519 [msg, sig, pk]
  (let [sig-bs (=>bytes sig)
        msg-bs (=>bytes msg)
        mlen (count msg-bs)
        pk-bs (=>bytes pk)
        ret (.crypto_sign_ed25519_verify_detached
              (NaCl/sodium)
              sig-bs
              msg-bs mlen
              pk-bs)]
    (if (= ret 0)
      {:ret ret :msg msg-bs :alg "ed25519" :signer pk}
      {:ret ret})))

(defprotocol ISignatureSign
  "Verify digital signature."
  (sign [this msg]))

(defprotocol ISignatureVerify
  "Verify digital signature."
  (verify [this msg+sig] [this msg sig]))

(defrecord TEd25519Signer [kp]
  IFn
    (invoke [this msg] (sign this msg)))

(defrecord TEd25519Verifier [pk]
  IFn
    ;(invoke [this msg+sig](verify this msg+sig))
    (invoke [this msg sig](verify this msg sig)))

(defrecord TMessageSigned [msg sig alg signer])

(defrecord TMessageVerified [msg signer])

(extend-type TEd25519Verifier
  ISignatureVerify
    (verify
      ;([this msg+sig])
      ([this msg sig]
        (let [ret (verify-detached-ed25519 msg, sig, (:pk this))]
          (if (= (:ret ret) 0)
            (map->TMessageVerified ret)
            ret)))))



;;;
;naclj.core=> (def kp (kp/make-key-pair :sodium :ed25519))
;#'naclj.core/kp
;naclj.core=> (def s (sig/sign-detached-ed25519 "abc" (kp/private-key kp)))
;#'naclj.core/s
;naclj.core=> s
;{:alg "ed25519"
; :msg #<byte[] [B@7bbe11c7>
; :sig #<byte[] [B@24f5a3be>
; :sig-len 64
; :signer #naclj.key_ed25519.TEd25519PublicKey{:public-key-bs #<byte[] [B@3a88322b>}}
;naclj.core=> (sig/verify-detached-ed25519 "abc" (:sig s) (:signer s))
;{:alg "ed25519"
; :msg #<byte[] [B@42adcce8>
; :signer #naclj.key_ed25519.TEd25519PublicKey{:public-key-bs #<byte[] [B@3a88322b>}}
;naclj.core=> (sig/verify-detached-ed25519 "abcd" (:sig s) (:signer s))
;{:ret -1}
;naclj.core=>
