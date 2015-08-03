(ns naclj.encode-util
  (require [cognitect.transit :as t])
	(:import 
	  (java.util Arrays Base64)
	  (org.apache.commons.codec.binary)
	  (org.abstractj.kalium NaCl)
	  (org.abstractj.kalium NaCl$Sodium)
    ))

;; helper fn

(defn -keywd2str [k-or-s]
  "Converts a keyword into a string without the ':'.
  Used for Java interop by using keywords for string-constants."
  (if (string? k-or-s)
    k-or-s
    (if-let [n (namespace k-or-s)]
      (str n "/" (name k-or-s))
      (name k-or-s))))

(defn byte-array? [bs] 
  "Ugly convenience fn to check for byte-array type"
  (= (str (type bs)) "class [B"))

;;----

(defprotocol IEqual
  "Define object specific equality test"
  (equal? [this that]))

(extend-type (Class/forName "[B")
  IEqual
    (equal? [this that]
      (or (= this that)
          (if (instance? (Class/forName "[B") that)
            (java.util.Arrays/equals this that)
            false))))


(defprotocol IBytesEncode
  "Convert to byte array."
  (=>bytes [this][this char-set] 
  "Encode/converts object to byte array representation.
   Returned byte-array should be a clone from or not affect the source.
   If you know or are unsure, that changes will be made to the returned byte-array, then use this function.")
  (=>bytes! [this][this char-set] 
  "Encodes/converts object to byte array representation,
   Changes to returned byte array may affect original array's content.
   If you know that no changes will be made to the returned byte-array, then use this function."))

(defprotocol IString
  "Uudecode to string."
  (=>string [this][this char-set]))


(extend-type java.lang.String
  IBytesEncode
    (=>bytes
      ([this]
      (=>bytes this "UTF-8"))
      ([this char-set]
        (let [c (-keywd2str char-set)]
          (.getBytes this c))))
    (=>bytes! 
      ([this] (=>bytes this))
      ([this char-set] (=>bytes this char-set)))
  IString
    (=>string 
      ([this] this)
      ([this char-set] this))
  )

(extend-type (Class/forName "[B")
  IString
    (=>string 
      ([this]
        (String. this "UTF-8"))
      ([this char-set]
        (let [c (-keywd2str char-set)]
          (String. this c))))
  IBytesEncode
    (=>bytes 
      ([this] (aclone this))
      ([this char-set] (aclone this)))
    (=>bytes! 
      ([this] this)
      ([this char-set] this)))


;;

(defprotocol IHexEncode
  "Encode to hex."
  (=>hex [this])
  (=>hex-str [this]))

(defprotocol IHexDecode
  "Decode from hex."
  (hex=> [this])
  (hex? [this]))

(defprotocol Ibase64urlEncode
  "Encode to base64url array"
  (=>base64url [this])
  (=>base64url-str [this])
  )

(defprotocol Ibase64urlDecode
  "Decode from base64url array to bytes"
  (base64url=> [this])
  )


(extend-type java.lang.String
  IHexEncode
    (=>hex [s]
      (.encode (org.apache.commons.codec.binary.Hex.) (bytes (=>bytes! s))))
    (=>hex-str [s]
      (org.apache.commons.codec.binary.Hex/encodeHexString (=>bytes! s)))
  IHexDecode
    (hex=> [s]
      (.decode (org.apache.commons.codec.binary.Hex.) (bytes (=>bytes! s))))
  Ibase64urlEncode
    (=>base64url-str [s]
      ;; encodes string (utf8) to a base64url string without padding
      (let [encoder (.withoutPadding (java.util.Base64/getUrlEncoder))]
        (.encodeToString encoder (=>bytes! s "UTF-8"))))
    (=>base64url [s]
      ;; encodes string to a base64url byte array without padding
      (let [encoder (.withoutPadding (java.util.Base64/getUrlEncoder))]
        (.encode encoder (=>bytes! s "UTF-8"))))
  Ibase64urlDecode
    (base64url=> [s]
      ;; decodes base64url string to binary byte array
      (let [decoder (java.util.Base64/getUrlDecoder)]
        (.decode decoder s))))


(extend-type (Class/forName "[B")
  IHexEncode
    (=>hex [bs]
      (.encode (org.apache.commons.codec.binary.Hex.) (bytes bs)))
             ;; unclear why that casting is needed (?) ^^^^^
    (=>hex-str [bs]
      (org.apache.commons.codec.binary.Hex/encodeHexString (bytes bs)))
  IHexDecode
    (hex=> [bs]
      (.decode (org.apache.commons.codec.binary.Hex.) (bytes bs)))
  Ibase64urlEncode
    (=>base64url-str [bs]
      ;; encodes binary byte array to a base64url string without padding
      (let [encoder (.withoutPadding (java.util.Base64/getUrlEncoder))]
        (.encodeToString encoder bs)))
    (=>base64url [bs]
      ;; encodes binary byte array to a base64url byte array without padding
      (let [encoder (.withoutPadding (java.util.Base64/getUrlEncoder))]
        (.encode encoder bs)))
  Ibase64urlDecode
    (base64url=> [bs]
      ;; decodes base64url byte array to binary byte array
      (let [decoder (java.util.Base64/getUrlDecoder)]
        (.decode decoder bs))))


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
  (namespace-name [this]
    "Returns the string of the namespace of this URN, i.e. the string fragment 
    after \"urn:\" and before the first \":\" separator, or nil.
    e.g.: (namespace-name \"urn:abc:def\" => \"abc\"
          (namespace-name \"http://xyz.com/def\" => nil")
  (sub-namespace-names [this]
    "Returns the namespace and sub-namespace names as a sequence (vector) of strings, or nil.
    e.g.: (sub-namespace-names \"urn:abc:def\" => [\"abc\"]
          (sub-namespace-names \"urn:abc:def:ghi:jkl\" => [\"abc\" \"def\" \"ghi\" ]")
  (namespace-specific-string [this]
    "Returns the namespace specific string, i.e. the string fragment after the last 
    sub-namespace designator, or nil. Note that empty string may be returned for valid 
    urn without a namespace specific string.
    e.g.: (namespace-specific-string \"urn:abc:def\" => \"def\"
          (namespace-specific-string \"urn:xyz:\" => \"\"
          (namespace-specific-string \"urn:abc:def:ghi:jkl#mno\" => \"jkl#mno\"")
  )

; urn-regex: "^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.:=@;$_!*'%/?#]+$"
; urn-regex: "^urn:[a-z0-9][a-z0-9-]{0,31}:[a-z0-9()+,\-.=@;$_!*'%/?#]+$"
; urn-regex: "^urn:([a-z0-9][a-z0-9-]{0,31}:)+[a-z0-9()+,\-.=@;$_!*'%/?#]+$"
; urn-regex: "^urn:(([a-zA-Z0-9][a-zA-Z0-9-]{0,31}:)+)([a-zA-Z0-9()+,\-.=@;$_!*'%/?#]*)$"
;   "^(?i)^urn(?-i):[a-z]{1,31}(:([\\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)+(\\?\\w+(=([\\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)?(&\\w+(=([\\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)?)*)?\\*?$"
;   "^(?i)^urn(?-i):[a-z]{1,31}(:([\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)+(\?\w+(=([\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)?(&\w+(=([\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)?)*)?\*?$"
;   "^(?i)^urn(?-i):[a-z]{1,31}(:([\\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)+(\\?\\w+(=([\\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)?(&\\w+(=([\\-a-zA-Z0-9/]|%[0-9a-fA-F]{2})*)?)*)?\\*?$"

;;;

(defprotocol IJoseRepresentation
  "Returning a JOSE representation of the object."
  (jose [this]))


;;----

(defn make-random-bytes
  "Returns a new byte-array of size n filled with random values."
  [n] 
  (let [bs (byte-array n)]
    (.randombytes (NaCl/sodium) bs n)
    bs))

(defn make-random-bytes!
  "Fills the whole byte array bs with random values.
  Changes the provided array content in-place.
  Returns the same changed array."
  [bs] 
  (.randombytes (NaCl/sodium) bs (count bs))
  bs)
