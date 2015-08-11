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
;;; #&lt;Var@1e5dee77: 
;;;   {:private-key
;;;    {:private-key-bs
;;;     [-98, 9, 23, -73, 113, -86, -117, -10, 8, 123, 36, -5, 117, -102,
;;;      -33, -27, -29, 76, 103, -43, -46, -23, 108, 123, 34, 12, -124,
;;;      -70, 102, 61, 35, 20]},
;;;    :public-key
;;;    {:public-key-bs
;;;     [-16, -74, 110, 122, 85, -4, 80, 82, 78, -125, -19, 45, 115, 68,
;;;      -71, 96, 40, -5, 6, 81, -47, 2, 82, 95, -90, 19, -62, -88, -105,
;;;      9, -96, 116]}}&gt;
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
;;; #&lt;Var@1e709494: 
;;;   {:public-key-bs
;;;    [-62, -58, 56, -97, 1, -70, 78, 106, 21, -106, -14, -65, 36, -76,
;;;     106, 64, 107, 45, 99, -2, 104, -28, 92, -112, 118, -26, 92, 62,
;;;     -61, -69, 70, 103]}&gt;
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
;;; #&lt;Var@147b278: 
;;;   {:key-bs
;;;    [101, -82, -25, -19, -75, -24, 127, -125, -43, -41, -103, 14, 88,
;;;     108, 37, -101, -45, -30, 10, 20, 42, -40, -37, -88, 17, 112, 120,
;;;     10, -126, 106, 32, 67],
;;;    :public-key-A
;;;    {:public-key-bs
;;;     [-16, -74, 110, 122, 85, -4, 80, 82, 78, -125, -19, 45, 115, 68,
;;;      -71, 96, 40, -5, 6, 81, -47, 2, 82, 95, -90, 19, -62, -88, -105,
;;;      9, -96, 116]},
;;;    :public-key-B
;;;    {:public-key-bs
;;;     [-62, -58, 56, -97, 1, -70, 78, 106, 21, -106, -14, -65, 36, -76,
;;;      106, 64, 107, 45, 99, -2, 104, -28, 92, -112, 118, -26, 92, 62,
;;;      -61, -69, 70, 103]},
;;;    :id-xor
;;;    [50, 112, 86, -27, 84, 70, 30, 56, 91, 21, 31, -110, 87, -16, -45,
;;;     32, 67, -42, 101, -81, -71, -26, 14, -49, -48, -11, -98, -106, 84,
;;;     -78, -26, 19]}&gt;
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
;;; #&lt;Var@6bf2c670: 
;;;   {:key-bs
;;;    [101, -82, -25, -19, -75, -24, 127, -125, -43, -41, -103, 14, 88,
;;;     108, 37, -101, -45, -30, 10, 20, 42, -40, -37, -88, 17, 112, 120,
;;;     10, -126, 106, 32, 67],
;;;    :public-key-A
;;;    {:public-key-bs
;;;     [-62, -58, 56, -97, 1, -70, 78, 106, 21, -106, -14, -65, 36, -76,
;;;      106, 64, 107, 45, 99, -2, 104, -28, 92, -112, 118, -26, 92, 62,
;;;      -61, -69, 70, 103]},
;;;    :public-key-B
;;;    {:public-key-bs
;;;     [-16, -74, 110, 122, 85, -4, 80, 82, 78, -125, -19, 45, 115, 68,
;;;      -71, 96, 40, -5, 6, 81, -47, 2, 82, 95, -90, 19, -62, -88, -105,
;;;      9, -96, 116]},
;;;    :id-xor
;;;    [50, 112, 86, -27, 84, 70, 30, 56, 91, 21, 31, -110, 87, -16, -45,
;;;     32, 67, -42, 101, -81, -71, -26, 14, -49, -48, -11, -98, -106, 84,
;;;     -78, -26, 19]}&gt;
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
;;; #&lt;Var@638849fb: 
;;;   {:private-key
;;;    {:private-key-bs
;;;     [8, 49, 90, 92, -42, -73, 76, -74, -87, 66, 54, 75, 43, -110, -99,
;;;      -100, 63, 33, 68, -73, -11, -53, -81, 44, 44, 112, -57, -81, 14,
;;;      40, -15, -39, 1, 84, 107, -41, -50, 21, -57, -113, 7, 114, -52,
;;;      115, 15, -20, -86, 69, 32, 8, 44, -93, -65, -65, 0, 114, 67, 20,
;;;      -21, -91, 45, 19, 20, 2]},
;;;    :public-key
;;;    {:public-key-bs
;;;     [1, 84, 107, -41, -50, 21, -57, -113, 7, 114, -52, 115, 15, -20,
;;;      -86, 69, 32, 8, 44, -93, -65, -65, 0, 114, 67, 20, -21, -91, 45,
;;;      19, 20, 2]}}&gt;
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
;;; #&lt;Var@7aa282ef: 
;;;   {:private-key-bs
;;;    [8, 49, 90, 92, -42, -73, 76, -74, -87, 66, 54, 75, 43, -110, -99,
;;;     -100, 63, 33, 68, -73, -11, -53, -81, 44, 44, 112, -57, -81, 14,
;;;     40, -15, -39, 1, 84, 107, -41, -50, 21, -57, -113, 7, 114, -52,
;;;     115, 15, -20, -86, 69, 32, 8, 44, -93, -65, -65, 0, 114, 67, 20,
;;;     -21, -91, 45, 19, 20, 2]}&gt;
;;; #&lt;Var@6d8c6c4d: 
;;;   {:public-key-bs
;;;    [1, 84, 107, -41, -50, 21, -57, -113, 7, 114, -52, 115, 15, -20,
;;;     -86, 69, 32, 8, 44, -93, -65, -65, 0, 114, 67, 20, -21, -91, 45,
;;;     19, 20, 2]}&gt;
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
;;; &quot;Za7n7bXof4PV15kOWGwlm9PiChQq2NuoEXB4CoJqIEM&quot;
;;; &quot;C2yejHmGapO411PxRo_eHogjSM78y-AKn-i-9eGuGQ0&quot;
;;; 
;; <-
;; =>
;;; {"type":"html","content":"<span class='clj-nil'>nil</span>","value":"nil"}
;; <=
