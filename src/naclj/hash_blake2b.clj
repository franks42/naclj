(ns naclj.hash-blake2b
	(:import 
	  (org.abstractj.kalium NaCl)
	  (org.abstractj.kalium NaCl$Sodium)
    [clojure.lang IFn]
    [clojure.lang.AFn])
	(:require 
	  [naclj.hash-protocol :refer :all]
	  [naclj.encode-util :refer :all]
	  [naclj.fixture :as f]))

;; sodium constants
(def generichash-bytes-min (.crypto_generichash_bytes_min (NaCl/sodium)))
(def generichash-bytes-max (.crypto_generichash_bytes_max (NaCl/sodium)))
(def generichash-bytes (.crypto_generichash_bytes (NaCl/sodium)))
(def generichash-keybytes-min (.crypto_generichash_keybytes_min (NaCl/sodium)))
(def generichash-keybytes-max (.crypto_generichash_keybytes_max (NaCl/sodium)))
(def generichash-keybytes (.crypto_generichash_keybytes (NaCl/sodium)))
(def generichash-statebytes (.crypto_generichash_statebytes (NaCl/sodium)))

(def blake2b-bytes-min (.crypto_generichash_blake2b_bytes_min (NaCl/sodium)))
(def blake2b-bytes-max (.crypto_generichash_blake2b_bytes_max (NaCl/sodium)))
(def blake2b-bytes (.crypto_generichash_blake2b_bytes (NaCl/sodium)))
(def blake2b-keybytes-min (.crypto_generichash_blake2b_keybytes_min (NaCl/sodium)))
(def blake2b-keybytes-max (.crypto_generichash_blake2b_keybytes_max (NaCl/sodium)))
(def blake2b-keybytes (.crypto_generichash_blake2b_keybytes (NaCl/sodium)))
(def blake2b-saltbytes (.crypto_generichash_blake2b_saltbytes (NaCl/sodium)))
(def blake2b-personalbytes (.crypto_generichash_blake2b_personalbytes (NaCl/sodium)))




;;;
(defrecord TBlake2bMessageDigester [msg-digest-state digest-size provider algorithm char-set]
  IFn
    (invoke [this]
      (digest this))
    (invoke [this s0](digest this [s0]))
    (invoke [this s0 s1](digest this [s0 s1]))
    (invoke [this s0 s1 s2](digest this [s0 s1 s2]))
    (invoke [this s0 s1 s2 s3](digest this [s0 s1 s2 s3]))
    (invoke [this s0 s1 s2 s3 s4](digest this [s0 s1 s2 s3 s4]))
    (invoke [this s0 s1 s2 s3 s4 s5](digest this [s0 s1 s2 s3 s4 s5]))
    (invoke [this s0 s1 s2 s3 s4 s5 s6](digest this [s0 s1 s2 s3 s4 s5 s6]))
    (invoke [this s0 s1 s2 s3 s4 s5 s6 s7](digest this [s0 s1 s2 s3 s4 s5 s6 s7]))
    (invoke [this s0 s1 s2 s3 s4 s5 s6 s7 s8](digest this [s0 s1 s2 s3 s4 s5 s6 s7 s8]))
    (invoke [this s0 s1 s2 s3 s4 s5 s6 s7 s8 s9](digest this [s0 s1 s2 s3 s4 s5 s6 s7 s8 s9]))
    (applyTo [this args] 
      (clojure.lang.AFn/applyToHelper this args))
  )

(extend-type TBlake2bMessageDigester
  IMessageDigester
  (update [this bytes-or-str]
    (-update! (assoc this :msg-digest-state (aclone (:msg-digest-state this))) bytes-or-str))
  (-update! [this bytes-or-str]
    (if (coll? bytes-or-str)
      (reduce -update! this bytes-or-str)
      (let [in-bs (=>bytes bytes-or-str)
            ret (.crypto_generichash_blake2b_update 
                  (NaCl/sodium) 
                  (:msg-digest-state this)
                  in-bs (count in-bs))]
        (if (= ret 0)
          this
          nil))))
  (digest 
    ([this]
      (let [b-a (byte-array (:digest-size this))
            ret (.crypto_generichash_blake2b_final 
                  (NaCl/sodium) 
                  (aclone (:msg-digest-state this))
                  b-a (count b-a))]
        (if (= ret 0)
          (->TMessageDigest b-a (:algorithm this))
          nil)))
    ([this bytes-or-str]
      (digest (update this bytes-or-str))))
  )



;public int crypto_generichash_blake2b_init_salt_personal(@Out byte[] state, 
;                                           @In byte[] key, @u_int64_t long keylen, 
;                                           @u_int64_t long outlen,
;                                           @In byte[] salt, @In byte[] personal);

;; (def make-sodium-digester (partial make-message-digester :sodium))
(defmethod make-message-digester [:sodium :blake2b]
  [provider function & {:keys [digest-size char-set key salt personal] :as xs}]
  (let [c (if char-set char-set :utf8)
        d-s (if digest-size digest-size blake2b-bytes)
        k (if key key nil)
        k-s (if key (count key) 0)
        s (if salt salt nil)
        p (if personal personal nil)
        outbytes (if (= d-s :max) blake2b-bytes-max
                   (if (= d-s :min) blake2b-bytes-min
                     d-s))
        digest-state (byte-array generichash-statebytes)
        ret (.crypto_generichash_blake2b_init_salt_personal 
                   (NaCl/sodium) 
                   digest-state 
                   k k-s
                   outbytes
                   s p)]
    (if (= ret 0)
      (TBlake2bMessageDigester. 
        digest-state 
        outbytes
        :sodium 
        :blake2b
        c)
      nil)))

;(defmethod make-message-digester [:sodium :blake2b]
;  [provider function & {:keys [digest-size char-set key] :as xs}]
;  (let [c (if char-set char-set :utf8)
;        d-s (if digest-size digest-size blake2b-bytes)
;        k (if key key nil)
;        k-s (if key (count key) 0)
;        outbytes (if (= d-s :max) blake2b-bytes-max
;                   (if (= d-s :min) blake2b-bytes-min
;                     d-s))
;        digest-state (byte-array generichash-statebytes)
;        ret (.crypto_generichash_blake2b_init 
;                   (NaCl/sodium) 
;                   digest-state 
;                   k k-s
;                   outbytes)]
;    (if (= ret 0)
;      (TBlake2bMessageDigester. 
;        digest-state 
;        outbytes
;        :sodium 
;        :blake2b
;        c)
;      nil)))



