(ns naclj.key-protocol
  (:require [naclj.encode-util :refer :all]))

;;

(defprotocol IKey
  "Describes the functionality of a key."
  (->pem! [this file-path])
  (encoded [this])
  (encoding-format [this])
  (pair? [this that])
  )

(defprotocol IKeyPair
  "Describes the functionality of a keypair."
  (private-key [this])
  (public-key [this])
  (key-pair [this])
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

(defmethod key-pair? :default [o] false)
(defmethod private-key? :default [o] false)
(defmethod public-key? :default [o] false)

;;;

(defrecord TGenericKey [key-bs])

(defmulti make-key
  (fn [provider function & xs] [provider function]))

(defmethod make-key :default
  [provider function & {:keys [size] :as xs}]
  (map->TGenericKey :key-bs (make-random-bytes size)
                    :provider :sodium))

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


;;;
