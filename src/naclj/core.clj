(ns naclj.core
	(:require 
	  [naclj.hash-protocol :as hp]
	  [naclj.key-protocol :as kp]
	  [naclj.key-curve25519]
	  [naclj.key-ed25519]
	  [naclj.signature-ed25519 :as sig]
	  [naclj.hash-blake2b]
	  [naclj.hash-sha256]
	  [naclj.hash-sha512]
	  [naclj.jose]
	  [naclj.encode-util :refer :all]
	  [naclj.uri-util :refer :all]
	  [naclj.fixture :as f]
	  [clojure.tools.namespace.repl :refer [refresh]]
	  ;[clj-ns-browser.sdoc :as b]
	  [clojure.java.io :refer [reader writer]]
	  ))


(defn -main [& args])

;;;

;(extend-type org.abstractj.kalium.keys.KeyPair
;  IKeyPair
;    (key-pair [this] this)
;    (private-key [this] (.getPrivateKey this))
;    (public-key [this] (.getPublicKey this))
;    (key-pair= [this that]
;      (if (satisfies? IKeyPair that)
;       (or (= this that) 
;           (key= (private-key this) (private-key that)))
;       false))
;  IEqual
;    (equal? [this that] (key-pair= this that))
;  )
;
;(extend-type org.abstractj.kalium.keys.PublicKey
;  IKey
;    (key-length [this] org.abstractj.kalium.NaCl$Sodium/PUBLICKEY_BYTES)
;    (algorithm [this] "curve25519xsalsa20poly1305")
;    (key= [this that]
;      (if (public-key? that)
;       (or (= this that) (= (str this) (str that)))
;       false))
;    (pair? [this that]
;      (and (private-key? that)
;           (key= this (public-key that))))
;  IBytesEncode
;    (=>bytes [this] (.toBytes this))
;  IHexEncode
;    (=>hex [this] (str this))
;  IEqual
;    (equal? [this that] (key= this that))
;  )
;
;(extend-type org.abstractj.kalium.keys.PrivateKey
;  IKeyPair
;    (key-pair [this] (KeyPair. (.toBytes this)))
;    (private-key [this] this)
;    (public-key [this] (public-key (key-pair this)))
;    (key-pair= [this that]
;      (if (= this that) true
;        (if (satisfies? IKeyPair that)
;          (key= this (private-key that))
;          false)))
;  IKey
;    (key-length [this] org.abstractj.kalium.NaCl$Sodium/SECRETKEY_BYTES)
;    (algorithm [this] "curve25519xsalsa20poly1305")
;    (key= [this that]
;      (if (private-key? that)
;       (or (= this that) (= (str this) (str that)))
;       false))
;    (pair? [this that]
;      (and (public-key? that)
;           (key= (public-key this) that)))
;  IBytesEncode
;    (=>bytes [this] (.toBytes this))
;  IHexEncode
;    (=>hex [this] (str this))
;  IEqual
;    (equal? [this that] (key= this that))
;  )
;
;
;(defmethod key-pair? org.abstractj.kalium.keys.KeyPair [o] true)
;(defmethod private-key? org.abstractj.kalium.keys.PrivateKey [o] true)
;(defmethod public-key? org.abstractj.kalium.keys.PublicKey [o] true)
;
;;; (def mkp-kalium (partial make-key-pair :kalium))
;(defmethod make-key-pair [:kalium :encrypt]
;  [provider function & {:keys [from] :as xs}]
;  (if (nil? xs)
;    (make-key-pair provider function :from (org.abstractj.kalium.keys.KeyPair.))
;    (let [bs from]
;      (if (key-pair? bs)
;      bs
;      (if (private-key? bs)
;        (org.abstractj.kalium.keys.KeyPair. (.toBytes bs))
;        (if (string? bs)
;          (org.abstractj.kalium.keys.KeyPair. (hex=> bs))
;          (org.abstractj.kalium.keys.KeyPair. bs)))))))
;
;;; (def mkp-kalium (partial make-key-pair :kalium))
;(defmethod make-key-pair [:kalium :sign]
;  [provider function & {:keys [from] :as xs}]
;  (if (nil? xs)
;    (make-key-pair provider function :from (org.abstractj.kalium.keys.SigningKey.))
;    (let [bs from]
;      (if (key-pair? bs)
;      bs
;      (if (private-key? bs)
;        (org.abstractj.kalium.keys.SigningKey. (.toBytes bs))
;        (if (string? bs)
;          (org.abstractj.kalium.keys.KeyPair. (hex=> bs))
;          (org.abstractj.kalium.keys.KeyPair. bs)))))))
;
;
;(defn make-key-pair2
;  ([] (org.abstractj.kalium.keys.KeyPair.))
;  ([bs] 
;    (if (key-pair? bs)
;      bs
;      (if (private-key? bs)
;        (org.abstractj.kalium.keys.KeyPair. (.toBytes bs))
;        (if (string? bs)
;          (org.abstractj.kalium.keys.KeyPair. (=>bytes bs))
;          (org.abstractj.kalium.keys.KeyPair. bs)))))
;  ([bs error-return] 
;    (try (make-key-pair2 bs)
;      (catch Exception e error-return))))
;
;(defn make-private-key [bs-or-str]
;  (if (string? (type bs-or-str))
;    (make-private-key (=>bytes bs-or-str))
;    (org.abstractj.kalium.keys.PrivateKey. bs-or-str)))
;
;(defn make-public-key [bs-or-str]
;  (if (string? (type bs-or-str))
;    (make-public-key (=>bytes bs-or-str))
;    (org.abstractj.kalium.keys.PublicKey. bs-or-str)))
;
;;;;
;
;(defn make-random-bytes
;  ([] (.randomBytes (org.abstractj.kalium.crypto.Random.)))
;  ([n-or-key] 
;    (if (satisfies? IKey n-or-key)
;      (make-random-bytes (key-length n-or-key))
;      (.randomBytes (org.abstractj.kalium.crypto.Random.) n-or-key))))
;

;;;
