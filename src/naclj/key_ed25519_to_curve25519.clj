(ns naclj.key-ed25519-to-curve25519
  "Conversion functions from ed25519 to curve25519 functions implemented as protocol extensions of TEd25519* records."
	(:require 
	  [naclj.key-protocol :refer :all]
	  [naclj.encode-util :refer :all]
	  [naclj.key-ed25519 :as ed]
	  [naclj.key-curve25519 :refer :all])
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
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
      (let [curve25519_sk (byte-array curve25519-secretkeybytes)
            r (.crypto_sign_ed25519_sk_to_curve25519 (NaCl/sodium)
                curve25519_sk (=>bytes! this))]
        (when r (map->TCurve25519PrivateKey {:private-key-bs curve25519_sk})))))

(extend-type TEd25519PublicKey
  IPKeyEdToCurve25519
    (curve25519-public-key 
      [this]
      (let [curve25519_pk (byte-array curve25519-publickeybytes)
            r (.crypto_sign_ed25519_pk_to_curve25519 (NaCl/sodium)
                curve25519_pk (=>bytes! this))]
        (when r (map->TCurve25519PublicKey {:public-key-bs curve25519_pk})))))
