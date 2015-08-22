(ns naclj.encode-util
  (:require [cognitect.transit :as t])
	(:import 
	  (java.util Arrays Base64)
	  (org.apache.commons.codec.binary)
    ))

;; helper fn

(defn -keywd2str
  "Converts a keyword into a string without the ':'.
  Used for Java interop by using keywords for string-constants."
  [k-or-s]
  (if (string? k-or-s)
    k-or-s
    (if-let [n (namespace k-or-s)]
      (str n "/" (name k-or-s))
      (name k-or-s))))

(defn byte-array? 
  "Ugly convenience fn to check for byte-array type"
  [bs]
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
      ([this char-set] this)))

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
  (=>base64url-str [this]))

(defprotocol Ibase64urlDecode
  "Decode from base64url array to bytes"
  (base64url=> [this]))


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

;;;

(defprotocol IJoseRepresentation
  "Returning a JOSE representation of the object."
  (jose [this]))

;;;
