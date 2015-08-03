(ns naclj.protocol)
	
;(defprotocol IEqual
;  "Define object specific equality test"
;  (equal? [this that]))
;
;(extend-type (Class/forName "[B")
;  IEqual
;    (equal? [this that]
;      (or (= this that)
;          (if (instance? (Class/forName "[B") that)
;            (java.util.Arrays/equals this that)
;            false))))
;
;;

(defprotocol IKey
  "Describes the functionality of a key."
  (key-length [this])
  (->pem! [this file-path])
  (algorithm [this])
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

;;

(defmulti key-pair? type)
(defmulti private-key? type)
(defmulti public-key? type)

(defmulti make-key-pair
  (fn [provider function & xs] [provider function]))

(defmethod key-pair? :default [o] false)
(defmethod private-key? :default [o] false)
(defmethod public-key? :default [o] false)


