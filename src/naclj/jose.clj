(ns naclj.jose
	(:require 
	  [naclj.key-protocol :refer :all]
	  [naclj.hash-protocol :as hp]
	  [naclj.encode-util :refer :all]
	  [naclj.fixture :as f]
	  [naclj.key-curve25519]  ;; first require ns of records
	  [naclj.hash-sha256]
	  [clojure.java.io :refer [reader writer]])
	(:import
	  ;; now import each record - note "_" because of java interop-crap...:-(
	  [naclj.key_curve25519 TCurve25519KeyPair TCurve25519PrivateKey 
	                        TCurve25519PublicKey TCurve25519DHKey]))


(extend-type TCurve25519KeyPair
 IJoseRepresentation
   (jose [this] [(jose (private-key this)) (jose (public-key this))]))

(extend-type TCurve25519PrivateKey
  IJoseRepresentation
    (jose [this] {"kty" "EC", 
                  "crv" "curve25519", 
                  "sk" (=>base64url-str (=>bytes this)),
                  "use" "dec", 
                  "kid" (=>base64url-str (=>bytes (public-key this)))}))

(extend-type TCurve25519PublicKey
  IJoseRepresentation
    (jose [this] {"kty" "EC", 
                  "crv" "curve25519", 
                  "pk" (=>base64url-str (=>bytes this)),
                  "use" "enc", 
                  "kid" (=>base64url-str (=>bytes this))}))

(extend-type TCurve25519DHKey
  IJoseRepresentation
    (jose [this] {"kty" "oct", 
                  "k" (=>base64url-str (=>bytes this)),
                  "kid" (=>base64url-str ((hp/make-message-digester :sodium :sha256) 
                                           (=>bytes this)))}))




(comment 

)
