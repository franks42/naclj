(ns naclj.key-ed25519-to-curve25519
	(:require 
	  [naclj.key-protocol :refer :all]
	  [naclj.encode-util :refer :all]
	  [naclj.key-ed25519 :as ed]
	  [naclj.key-curve25519 :refer :all])
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
	  (jnr.ffi.byref.LongLongByReference)
	  (java.net.URI)
	  ;; now import each record - note "_" because of java interop-crap...:-(
	  [naclj.key_ed25519 TEd25519KeyPair TEd25519PrivateKey TEd25519PublicKey]
	  [naclj.key_curve25519 TCurve25519KeyPair TCurve25519PrivateKey 
	                        TCurve25519PublicKey]))


(extend-type TEd25519KeyPair
  ISKeyEdToCurve25519
    (curve25519-private-key [this]
      (curve25519-private-key (private-key this)))
  IPKeyEdToCurve25519
    (curve25519-public-key [this]
      (curve25519-public-key (public-key this))))

(extend-type TEd25519PrivateKey
  ISKeyEdToCurve25519
    (curve25519-private-key
      [this]
      (let [curve25519_sk (byte-array secretkeybytes)
            r (.crypto_sign_ed25519_sk_to_curve25519 (NaCl/sodium)
                curve25519_sk (=>bytes! this))]
        (when r (map->TCurve25519PrivateKey {:private-key-bs curve25519_sk})))))

(extend-type TEd25519PublicKey
  IPKeyEdToCurve25519
    (curve25519-public-key 
      [this]
      (let [curve25519_pk (byte-array publickeybytes)
            r (.crypto_sign_ed25519_pk_to_curve25519 (NaCl/sodium)
                curve25519_pk (=>bytes! this))]
        (when r (map->TCurve25519PublicKey {:public-key-bs curve25519_pk})))))

;;;

;naclj.core=> (require 'naclj.key-ed25519-to-curve25519)
;nil
;naclj.core=> (def kp-a (kp/make-key-pair :sodium :ed25519))
;#'naclj.core/kp-a
;naclj.core=> kp-a
;#naclj.key_ed25519.TEd25519KeyPair{:private-key #naclj.key_ed25519.TEd25519PrivateKey{:private-key-bs #object["[B" 0x22d68bef "[B@22d68bef"]}, :public-key #naclj.key_ed25519.TEd25519PublicKey{:public-key-bs #object["[B" 0xa9c9a89 "[B@a9c9a89"]}}
;naclj.core=> (kp/curve25519-public-key kp-a)
;#naclj.key_curve25519.TCurve25519PublicKey{:public-key-bs #object["[B" 0x67a5560e "[B@67a5560e"]}
;naclj.core=> (kp/curve25519-private-key kp-a)
;#naclj.key_curve25519.TCurve25519PrivateKey{:private-key-bs #object["[B" 0x7488c244 "[B@7488c244"]}
;naclj.core=> (kp/pair? (kp/curve25519-public-key kp-a) (kp/curve25519-private-key kp-a))
;true
;naclj.core=>

