(ns naclj.hash-protocol
  (:refer-clojure :exclude [update])
  (:require
    [naclj.uri-util :refer :all]
    [naclj.encode-util :refer :all])
	(:import 
	  (java.net.URI)))


(defprotocol IMessageDigester
  "Describes the functionality of a digester."
  (update [this bytes-or-str]
  "Returns a new updated digest-state object. Original state is not changed.")
  (-update! [this bytes-or-str]
  "Internal function - Makes the updates to the digest-state in-place... do not use!")
  (digest [this][this bytes-or-str]
  "First updates the digest by hashing the parameter values, then returns the resulting hash."))


(defmulti make-message-digester
  (fn [provider function & xs] [provider function]))

;;;



(defrecord TMessageDigest [msg-digest-bs algorithm])

(extend-type TMessageDigest
  IEqual
    (equal? [this that] (equal? (=>bytes this) (=>bytes that)))
  IHexEncode
    (=>hex [this] (=>hex (:msg-digest-bs this)))
    (=>hex-str [this] (=>hex-str (:msg-digest-bs this)))
  Ibase64urlEncode
    (=>base64url [this] (=>base64url (:msg-digest-bs this)))
    (=>base64url-str [this] (=>base64url-str (:msg-digest-bs this)))
  IBytesEncode
  ; clone the byte-array to ensure immutability
  (=>bytes [this] (aclone (:msg-digest-bs this)))
  IUriIdentify
    (uri [this]
      (java.net.URI. (str "urn:hash:" (:algorithm this) ":base64url:" (=>base64url-str (=>bytes this))))))
