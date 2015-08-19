(ns naclj.jose
	(:require 
	  [naclj.key-protocol :refer :all]
	  [naclj.hash-protocol :as hp]
	  [naclj.encode-util :refer :all]
	  [naclj.fixture :as f]
	  [naclj.key-curve25519]  ;; first require ns of records
	  [naclj.key-ed25519]  ;; first require ns of records
	  [naclj.hash-sha256]
    [naclj.uri-util :refer :all]
	  [clojure.java.io :refer [reader writer]])
	(:import
	  ;; now import each record - note "_" because of java interop-crap...:-(
	  [naclj.key_curve25519 TCurve25519KeyPair TCurve25519PrivateKey 
	                        TCurve25519PublicKey TCurve25519DHKey]
	  [naclj.key_ed25519 TEd25519KeyPair TEd25519PrivateKey 
	                        TEd25519PublicKey]))


; curve25519

(extend-type TCurve25519KeyPair
 IJoseRepresentation
   (jose [this] [(jose (private-key this)) (jose (public-key this))]))

(extend-type TCurve25519PrivateKey
  IJoseRepresentation
    (jose [this] {"kty" "EC", 
                  "crv" "curve25519", 
                  "sk" (=>base64url-str (=>bytes this)),
                  "key_ops" "deriveKey", 
                  "kid" (str (uri this))}))

(extend-type TCurve25519PublicKey
  IJoseRepresentation
    (jose [this] {"kty" "EC", 
                  "crv" "curve25519", 
                  "pk" (=>base64url-str (=>bytes this)),
                  "key_ops" "deriveKey", 
                  "kid" (str (uri this))}))

(extend-type TCurve25519DHKey
  IJoseRepresentation
    (jose [this] {"kty" "oct", 
                  "k" (=>base64url-str (=>bytes this)),
                  "kid" (str (uri this))}))


; ed25519

(extend-type TEd25519KeyPair
 IJoseRepresentation
   (jose [this] [(jose (private-key this)) (jose (public-key this))]))

(extend-type TEd25519PrivateKey
  IJoseRepresentation
    (jose [this] {"kty" "EC", 
                  "crv" "ed25519", 
                  "sk" (=>base64url-str (=>bytes this)),
                  "key_ops" "sign", 
                  "kid" (str (uri this))}))

(extend-type TEd25519PublicKey
  IJoseRepresentation
    (jose [this] {"kty" "EC", 
                  "crv" "ed25519", 
                  "pk" (=>base64url-str (=>bytes this)),
                  "key_ops" "verify", 
                  "kid" (str (uri this))}))




(comment 

)
