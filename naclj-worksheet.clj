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
(require '[naclj.fixture :as f])
(require '[naclj.hash-sha256])
(require '[naclj.hash-blake2b])
(require '[naclj.hash-protocol :as hp])
(require '[naclj.key-protocol :as kp])
(require '[naclj.key-curve25519 :as c])
(require '[naclj.key-ed25519 :as s])
(require '[clojure.pprint :refer [pp pprint]])

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
;;; #&lt;Var@dec9d08: 
;;;   {:private-key
;;;    {:private-key-bs
;;;     [92, -13, -54, 118, -3, 112, 1, 81, 104, -50, -50, -12, -101, 49,
;;;      3, -35, 127, -65, 115, -9, 84, -111, -104, -22, -69, 107, -5, -95,
;;;      -94, -31, -88, 12]},
;;;    :public-key
;;;    {:public-key-bs
;;;     [-124, -110, 76, -3, -46, 75, -121, -125, -45, -3, -106, 73, -23,
;;;      18, -30, 33, 64, 46, 75, -90, 44, 59, -55, 119, 19, 99, 36, 12,
;;;      -75, 67, 127, 116]}}&gt;
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

;; @@
On the other side of the country, Alice's friend Bob generates its own keypair:
;; @@

;; @@
(def bob-kp (kp/make-key-pair :sodium :curve25519))
(def bob-sk (kp/private-key bob-kp))
(def bob-pk (kp/public-key bob-kp))

(pp)
;; @@
;; ->
;;; #&lt;Var@2b586f4b: 
;;;   {:public-key-bs
;;;    [28, 88, -102, -84, 28, -85, 20, -69, 3, -67, -72, 58, -103, -69,
;;;     -69, 100, -45, 1, -16, -4, -16, 109, -109, -23, -1, 19, 118, 29,
;;;     108, -123, -128, 58]}&gt;
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
;;; #&lt;Var@3d374aef: 
;;;   {:key-bs
;;;    [80, 101, 34, 108, -39, 125, -23, -70, -29, -41, -28, 16, 42, 60,
;;;     -105, -84, -109, -120, 29, -16, -26, -16, 36, 127, -30, -71, 45,
;;;     30, 79, -16, 16, 57],
;;;    :public-key-A
;;;    {:public-key-bs
;;;     [-124, -110, 76, -3, -46, 75, -121, -125, -45, -3, -106, 73, -23,
;;;      18, -30, 33, 64, 46, 75, -90, 44, 59, -55, 119, 19, 99, 36, 12,
;;;      -75, 67, 127, 116]},
;;;    :public-key-B
;;;    {:public-key-bs
;;;     [28, 88, -102, -84, 28, -85, 20, -69, 3, -67, -72, 58, -103, -69,
;;;      -69, 100, -45, 1, -16, -4, -16, 109, -109, -23, -1, 19, 118, 29,
;;;      108, -123, -128, 58]},
;;;    :id-xor
;;;    [-104, -54, -42, 81, -50, -32, -109, 56, -48, 64, 46, 115, 112, -87,
;;;     89, 69, -109, 47, -69, 90, -36, 86, 90, -98, -20, 112, 82, 17, -39,
;;;     -58, -1, 78]}&gt;
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
;;; #&lt;Var@1c5eb0f8: 
;;;   {:key-bs
;;;    [80, 101, 34, 108, -39, 125, -23, -70, -29, -41, -28, 16, 42, 60,
;;;     -105, -84, -109, -120, 29, -16, -26, -16, 36, 127, -30, -71, 45,
;;;     30, 79, -16, 16, 57],
;;;    :public-key-A
;;;    {:public-key-bs
;;;     [28, 88, -102, -84, 28, -85, 20, -69, 3, -67, -72, 58, -103, -69,
;;;      -69, 100, -45, 1, -16, -4, -16, 109, -109, -23, -1, 19, 118, 29,
;;;      108, -123, -128, 58]},
;;;    :public-key-B
;;;    {:public-key-bs
;;;     [-124, -110, 76, -3, -46, 75, -121, -125, -45, -3, -106, 73, -23,
;;;      18, -30, 33, 64, 46, 75, -90, 44, 59, -55, 119, 19, 99, 36, 12,
;;;      -75, 67, 127, 116]},
;;;    :id-xor
;;;    [-104, -54, -42, 81, -50, -32, -109, 56, -48, 64, 46, 115, 112, -87,
;;;     89, 69, -109, 47, -69, 90, -36, 86, 90, -98, -20, 112, 82, 17, -39,
;;;     -58, -1, 78]}&gt;
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
;;; #&lt;Var@24930715: 
;;;   {:private-key
;;;    {:private-key-bs
;;;     [107, 66, -106, 25, -30, -118, 64, -69, 17, 70, 9, 15, 38, -43, 89,
;;;      36, 104, -10, -115, 39, -90, -109, -123, -108, 47, 54, -73, 2, 59,
;;;      -82, -77, 50, -99, 103, -26, -86, -16, 32, 25, -104, 4, -60, -73,
;;;      44, -8, -40, -90, -125, 3, -31, 56, 103, -28, -67, -39, -117, 30,
;;;      -23, 102, 2, 125, 84, 69, 12]},
;;;    :public-key
;;;    {:public-key-bs
;;;     [-99, 103, -26, -86, -16, 32, 25, -104, 4, -60, -73, 44, -8, -40,
;;;      -90, -125, 3, -31, 56, 103, -28, -67, -39, -117, 30, -23, 102, 2,
;;;      125, 84, 69, 12]}}&gt;
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
;;; #&lt;Var@61907549: 
;;;   {:private-key-bs
;;;    [107, 66, -106, 25, -30, -118, 64, -69, 17, 70, 9, 15, 38, -43, 89,
;;;     36, 104, -10, -115, 39, -90, -109, -123, -108, 47, 54, -73, 2, 59,
;;;     -82, -77, 50, -99, 103, -26, -86, -16, 32, 25, -104, 4, -60, -73,
;;;     44, -8, -40, -90, -125, 3, -31, 56, 103, -28, -67, -39, -117, 30,
;;;     -23, 102, 2, 125, 84, 69, 12]}&gt;
;;; #&lt;Var@165d182a: 
;;;   {:public-key-bs
;;;    [-99, 103, -26, -86, -16, 32, 25, -104, 4, -60, -73, 44, -8, -40,
;;;     -90, -125, 3, -31, 56, 103, -28, -67, -39, -117, 30, -23, 102, 2,
;;;     125, 84, 69, 12]}&gt;
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
(defn key-hash-id [bs]
  "In order to obtain an intrinsic identifier/name for a key/secret-key/private-key,
  we return the hash of that byte-array of that secret.
  To add an additional layer of security, we use a key'ed hashing algorithm where the hashing-key
  is the secret itself. 
  In order to obtain a hashing-key of the correct size, we actually hash the secret one time.
  The resulting byte-array hash value will be a univerally unique identifier for the secret, which
  does not leak any data from the secret itself.
  For easier consumption, the returned byte-array can be converted to hex or base64(url)."
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
;;; &quot;UGUibNl96brj1-QQKjyXrJOIHfDm8CR_4rktHk_wEDk&quot;
;;; &quot;fq9K0wy3PxFMe9yynK-gJMWefYGEg6JEfjPENNAoRm0&quot;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=

;; @@

;; @@
