;; gorilla-repl.fileformat = 1

;; **
;;; # NACLJ
;;; 
;;; Welcome.
;;; 
;;; ### Some initialization and house keeping.
;; **

;; @@
(use 'clojure.repl)

(require '[naclj.encode-util :refer :all])
(require '[naclj.uri-util :refer :all])
(require '[naclj.fixture :as f])
(require '[naclj.hash-sha256])
(require '[naclj.hash-blake2b])
(require '[naclj.hash-protocol :as hp])
(require '[naclj.key-protocol :as kp])
(require '[naclj.key-curve25519 :as c])
(require '[naclj.key-ed25519 :as s])
(require '[clojure.pprint :refer [pp pprint]])
(require '[clojure.tools.namespace.repl :refer [refresh]])

;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; **
;;; ## Elliptic Curves 
;;; 
;;; ### NaCl's Curve25519
;; **

;; **
;;; Alice creates a new keypair like this:
;; **

;; @@
(def alice-kp (kp/make-key-pair :sodium :curve25519))
(pp)
;; @@
;; ->
;;; #&lt;Var@25773b4c: 
;;;   {:private-key
;;;    {:private-key-bs
;;;     [12, -111, -70, -104, 96, 58, -45, -16, -4, -15, 7, -108, 115, 43,
;;;      -61, -73, -81, 58, -78, -100, 106, 68, 102, 114, -118, -33, -127,
;;;      61, -53, -90, 42, -68]},
;;;    :public-key
;;;    {:public-key-bs
;;;     [-23, 5, 54, -73, -124, 60, -118, -27, 1, -43, -14, -108, -84,
;;;      -104, 50, -61, 6, 6, 109, -88, -56, 118, -26, 67, -27, 113, -115,
;;;      -23, -2, -26, 36, 49]}}&gt;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; **
;;; She can obtain the associated public and private keys from the newly generate keypair with:
;; **

;; @@
(def alice-sk (kp/private-key alice-kp))
(def alice-pk (kp/public-key alice-kp))

;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-var'>#&#x27;user/alice-pk</span>","value":"#'user/alice-pk"}
;; <=

;; **
;;; On the other side of the country, Alice's friend Bob generates its own keypair:
;; **

;; @@
(def bob-kp (kp/make-key-pair :sodium :curve25519))
(def bob-sk (kp/private-key bob-kp))
(def bob-pk (kp/public-key bob-kp))

(pp)
;; @@
;; ->
;;; #&lt;Var@6e56b2c4: 
;;;   {:public-key-bs
;;;    [80, 3, 73, -128, 43, 66, 7, 118, 58, -62, -73, 92, 100, -61, 123,
;;;     -19, -10, -49, -34, 117, 28, 8, -54, 107, -101, -104, -95, -61,
;;;     -28, 96, -21, 123]}&gt;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; **
;;; Now... through some unspecified, magical means, Alice and Bob exchange their public keys...
;;; 
;;; Such that Alice will "know" [alice-sk, alice-pk, bob-pk], while Bob has access to [bob-sk, bob-pk, alice-pk].
;;; 
;;; Alice and Bob can now both derive a DH-key from this information:
;; **

;; @@
(def alice-bob-dh (kp/dh-key alice-kp bob-pk))
(pp)
;; @@
;; ->
;;; #&lt;Var@35d50231: 
;;;   {:key-bs
;;;    [-30, 52, 25, 8, -72, -116, -99, 72, 75, 3, -74, 118, 93, -119, 21,
;;;     -105, -84, 77, -59, -79, 104, -79, -15, -45, -64, -80, 68, 48, 0,
;;;     -121, 115, 56],
;;;    :public-key-A
;;;    {:public-key-bs
;;;     [-23, 5, 54, -73, -124, 60, -118, -27, 1, -43, -14, -108, -84,
;;;      -104, 50, -61, 6, 6, 109, -88, -56, 118, -26, 67, -27, 113, -115,
;;;      -23, -2, -26, 36, 49]},
;;;    :public-key-B
;;;    {:public-key-bs
;;;     [80, 3, 73, -128, 43, 66, 7, 118, 58, -62, -73, 92, 100, -61, 123,
;;;      -19, -10, -49, -34, 117, 28, 8, -54, 107, -101, -104, -95, -61,
;;;      -28, 96, -21, 123]},
;;;    :id-xor
;;;    [-71, 6, 127, 55, -81, 126, -115, -109, 59, 23, 69, -56, -56, 91,
;;;     73, 46, -16, -55, -77, -35, -44, 126, 44, 40, 126, -23, 44, 42, 26,
;;;     -122, -49, 74]}&gt;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; @@
(def bob-alice-dh (kp/dh-key bob-kp alice-pk))
(pp)
;; @@
;; ->
;;; #&lt;Var@5cf9174c: 
;;;   {:key-bs
;;;    [-30, 52, 25, 8, -72, -116, -99, 72, 75, 3, -74, 118, 93, -119, 21,
;;;     -105, -84, 77, -59, -79, 104, -79, -15, -45, -64, -80, 68, 48, 0,
;;;     -121, 115, 56],
;;;    :public-key-A
;;;    {:public-key-bs
;;;     [80, 3, 73, -128, 43, 66, 7, 118, 58, -62, -73, 92, 100, -61, 123,
;;;      -19, -10, -49, -34, 117, 28, 8, -54, 107, -101, -104, -95, -61,
;;;      -28, 96, -21, 123]},
;;;    :public-key-B
;;;    {:public-key-bs
;;;     [-23, 5, 54, -73, -124, 60, -118, -27, 1, -43, -14, -108, -84,
;;;      -104, 50, -61, 6, 6, 109, -88, -56, 118, -26, 67, -27, 113, -115,
;;;      -23, -2, -26, 36, 49]},
;;;    :id-xor
;;;    [-71, 6, 127, 55, -81, 126, -115, -109, 59, 23, 69, -56, -56, 91,
;;;     73, 46, -16, -55, -77, -35, -44, 126, 44, 40, 126, -23, 44, 42, 26,
;;;     -122, -49, 74]}&gt;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; **
;;; When you look carefully, you can see that the two byte-arrays ":key-bs" are identical, which is confirmed with:
;; **

;; @@
(equal? alice-bob-dh bob-alice-dh)
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-unkown'>true</span>","value":"true"}
;; <=

;; **
;;; #### Closer Inspection
;; **

;; **
;;; The private and public key sizes are:
;; **

;; @@
(kp/key-length alice-sk)
(pp)
(kp/key-length alice-pk)
(pp)
;; @@
;; ->
;;; 32
;;; 32
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; @@
(= alice-pk
   (kp/public-key alice-sk))

(equal? alice-pk
   (kp/public-key alice-sk))
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-unkown'>true</span>","value":"true"}
;; <=

;; **
;;; ### NaCl's Ed25519
;; **

;; @@
(def alice-signing-kp (kp/make-key-pair :sodium :ed25519))
(pp)
;; @@
;; ->
;;; #&lt;Var@4c75b48b: 
;;;   {:private-key
;;;    {:private-key-bs
;;;     [-54, 48, 52, 7, 13, -37, 3, 34, 125, 26, 1, -34, -70, 83, 44, -23,
;;;      66, 61, -28, -42, 11, -26, -78, -96, -19, -54, 14, -106, -47, -16,
;;;      107, 4, -65, 109, -2, 103, 19, -33, 69, -123, 78, 97, 60, -120,
;;;      124, 73, 17, 14, -85, -78, -124, -52, 63, -2, 116, 68, 31, 19,
;;;      -64, 63, 108, -66, 76, -88]},
;;;    :public-key
;;;    {:public-key-bs
;;;     [-65, 109, -2, 103, 19, -33, 69, -123, 78, 97, 60, -120, 124, 73,
;;;      17, 14, -85, -78, -124, -52, 63, -2, 116, 68, 31, 19, -64, 63,
;;;      108, -66, 76, -88]}}&gt;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; @@
(def alice-signing-key (kp/private-key alice-signing-kp))
(pp)
(def alice-verify-key (kp/public-key alice-signing-kp))
(pp)
;; @@
;; ->
;;; #&lt;Var@37163ef4: 
;;;   {:private-key-bs
;;;    [-54, 48, 52, 7, 13, -37, 3, 34, 125, 26, 1, -34, -70, 83, 44, -23,
;;;     66, 61, -28, -42, 11, -26, -78, -96, -19, -54, 14, -106, -47, -16,
;;;     107, 4, -65, 109, -2, 103, 19, -33, 69, -123, 78, 97, 60, -120,
;;;     124, 73, 17, 14, -85, -78, -124, -52, 63, -2, 116, 68, 31, 19, -64,
;;;     63, 108, -66, 76, -88]}&gt;
;;; #&lt;Var@34fffbce: 
;;;   {:public-key-bs
;;;    [-65, 109, -2, 103, 19, -33, 69, -123, 78, 97, 60, -120, 124, 73,
;;;     17, 14, -85, -78, -124, -52, 63, -2, 116, 68, 31, 19, -64, 63, 108,
;;;     -66, 76, -88]}&gt;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; @@
(equal? alice-verify-key (kp/public-key alice-signing-key))
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-unkown'>true</span>","value":"true"}
;; <=

;; @@
naclj.hash-blake2b/blake2b-keybytes-min
naclj.hash-blake2b/blake2b-keybytes
naclj.hash-blake2b/blake2b-keybytes-max
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-unkown'>64</span>","value":"64"}
;; <=

;; @@
(=	f/Blake2_DIGEST_WITH_SALT_PERSONAL
	(=>hex-str (hp/digest (hp/make-message-digester :sodium :blake2b 
                                  :digest-size :max
                                  :key (=>bytes f/Blake2_KEY) 
                                  :salt (=>bytes f/Blake2_SALT) 
                                  :personal (=>bytes f/Blake2_PERSONAL))  
                        f/Blake2_MESSAGE)))
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-unkown'>true</span>","value":"true"}
;; <=

;; @@
(defn key-hash-id
  "In order to obtain an intrinsic identifier/name for a key/secret-key/private-key,
  we return the hash of that byte-array of that secret.
  To add an additional layer of security, we use a key'ed hashing algorithm where the hashing-key
  is the secret itself. 
  In order to obtain a hashing-key of the correct size, we actually hash the secret one time.
  The resulting byte-array hash value will be a univerally unique identifier for the secret, which
  does not leak any data from the secret itself.
  For easier consumption, the returned byte-array can be converted to hex or base64(url)."
  [bs]
  (let [bs (=>bytes bs)
        ;; first hash the key byte-array to obtain a key-length we can use for the hashing-key
        h (hp/digest (hp/make-message-digester :sodium :blake2b) bs)
        ;; then use the hash value as the hashing-key to hash the original key
		kh (hp/digest (hp/make-message-digester :sodium :blake2b :key (=>bytes h)) bs)]
	;; return the resulting byte-array as the identifier to use.
    (=>bytes kh)))
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-var'>#&#x27;user/key-hash-id</span>","value":"#'user/key-hash-id"}
;; <=

;; @@
(kp/key-length alice-bob-dh)
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-unkown'>32</span>","value":"32"}
;; <=

;; @@
(def bs (=>bytes alice-bob-dh))
(pprint (=>base64url-str bs))
(hp/digest (hp/make-message-digester :sodium :blake2b) bs)
(def kid (key-hash-id alice-bob-dh))
(count kid)
(pprint (=>base64url-str kid))
;; @@
;; ->
;;; &quot;4jQZCLiMnUhLA7Z2XYkVl6xNxbFosfHTwLBEMACHczg&quot;
;;; &quot;o9C7EzU-ovhrGhjrm-4NArHElVmniLeU2n-o50LtKTM&quot;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; @@
(def u (java.net.URI. (str "urn:nacl:hash:"  "blake2b-p:" "base64url:" (=>base64url-str "ABCD"))))
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-var'>#&#x27;user/u</span>","value":"#'user/u"}
;; <=

;; @@
(pp)
;; @@
;; ->
;;; nil
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; @@
(urn? u)
(urn-ns u)
(urn-ns-string u)
(urn-ns+subns+string u)
;; @@
;; =>
;;; {"type":"html","content":"<span class='clj-string'>&quot;QUJDRA&quot;</span>","value":"\"QUJDRA\""}
;; <=

;; @@

;; @@

;; @@

;; @@
