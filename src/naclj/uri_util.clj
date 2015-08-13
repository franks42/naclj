(ns naclj.uri-util
	(:import (java.net.URI)))

(defprotocol IUriIdentify
  "Protocol to standardize the returning of a URI instance uniquely identifying the object."
  (uri [this]
    "Returns a URI instance uniquely identifying the object."))

(defprotocol IUrnParser
  "Set of functions to facilitate the parsing and interpretation of URNs.
  All functions work both on URI instances as well as uri-like strings."
  (urn? [this]
    "Returns whether or not this URI is designated as a URN with a \"urn:\" prefix.
    e.g.: (urn? \"urn:abc:def\" => true
          (urn? \"http://xyz.com/def\" => false")
  (urn-ns [this]
    "Returns the string of the namespace of this URN, i.e. the string fragment 
    after \"urn:\" and before the first \":\" separator, or nil.
    e.g.: (urn-ns \"urn:abc:def\" => \"abc\"
          (urn-ns \"http://xyz.com/def\" => nil")
  (urn-ns+subns [this]
    "Returns the namespace and sub-namespace names as a sequence (vector) of strings, or nil.
    e.g.: (urn-ns+subns \"urn:abc:def\" => [\"abc\"]
          (urn-ns+subns \"urn:abc:def:ghi:jkl\" => [\"abc\" \"def\" \"ghi\" ]")
  (urn-ns+subns+string [this]
    "Returns the namespace and sub-namespace names and ns-string as a sequence (vector) 
    of strings, or nil.
    e.g.: (urn-ns+subns+string \"urn:abc:def\" => [\"abc\" \"def\"]
          (urn-ns+subns+string \"urn:abc:def:ghi:jkl\" => [\"abc\" \"def\" \"ghi\"\"kl\" ]")
  (urn-ns-string [this]
    "Returns the namespace specific string, i.e. the string fragment after the last 
    sub-namespace designator, or nil. Note that empty string may be returned for valid 
    urn without a namespace specific string.
    e.g.: (urn-ns-string \"urn:abc:def\" => \"def\"
          (urn-ns-string \"urn:xyz:\" => \"\"
          (urn-ns-string \"urn:abc:def:ghi:jkl#mno\" => \"jkl#mno\"")
  )

;;

(def -regex-urn #"^(urn):([a-zA-Z0-9][a-zA-Z0-9-]{0,31}):(([a-zA-Z0-9][a-zA-Z0-9-]{0,31}:)*)([a-zA-Z0-9()+,\-.=@;$_!*'%/?#]*)$")

(def -regex-urn-subns #"^([a-zA-Z0-9][a-zA-Z0-9-]{0,31}):(([a-zA-Z0-9][a-zA-Z0-9-]{0,31}:)*)$")


(defn -parse-subns [s v]
  (loop [s s
         v v]
    (let [m (re-matches -regex-urn-subns s)]
     (if m
       (let [vv (conj v (nth m 1))
             rest (nth m 2)
             more (nth m 3)]
         (if more
           (recur rest vv)
           vv))
       v))))

(defn -parse-urn
  ""
  [s]
  (when-let [m (re-matches -regex-urn s)]
    (let [urn-ns (nth m 2)
          urn-ns-specific-str (nth m 5)
          urn-subns-names (when (nth m 4)
                            (-parse-subns (nth m 3) []))]
      (vec (remove nil? (flatten [urn-ns urn-subns-names urn-ns-specific-str]))))))

;;

;; (java.net.URI. (str "urn:hash:" (:algorithm this) ":base64url:" (=>base64url-str (=>bytes this))))

(extend-type java.net.URI
  IUriIdentify
    (uri [this] this)
  IUrnParser
    (urn? [this]
      (if (-parse-urn (str this)) true false))
    (urn-ns [this]
      (when-let [m (-parse-urn (str this))] (first m)))
    (urn-ns+subns [this]
      (when-let [m (-parse-urn (str this))] (vec (butlast m))))
    (urn-ns+subns+string [this]
      (-parse-urn (str this)))
    (urn-ns-string [this]
      (when-let [m (-parse-urn (str this))] (last m))))

(extend-type java.lang.String
  IUrnParser
    (urn? [this]
      (if (-parse-urn this) true false))
    (urn-ns [this]
      (when-let [m (-parse-urn this)] (first m)))
    (urn-ns+subns [this]
      (when-let [m (-parse-urn this)] (vec (butlast m))))
    (urn-ns+subns+string [this]
      (-parse-urn this))
    (urn-ns-string [this]
      (when-let [m (-parse-urn this)] (last m))))


