(ns naclj.hash-sha512
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
    [clojure.lang IFn]
    [clojure.lang.AFn])
	(:require 
	  [naclj.hash-protocol :refer :all]
	  [naclj.encode-util :refer :all]
	  [naclj.fixture :as f]))


;; sodium constants
(def hash-sha512-bytes (.crypto_hash_sha512_bytes (NaCl/sodium)))
(def hash-sha512-statebytes (.crypto_hash_sha512_statebytes (NaCl/sodium)))

(def hmacsha512-bytes (.crypto_auth_hmacsha512_bytes (NaCl/sodium)))
(def hmacsha512-keybytes (.crypto_auth_hmacsha512_keybytes (NaCl/sodium)))
(def hmacsha512-statebytes (.crypto_auth_hmacsha512_statebytes (NaCl/sodium)))


;;;

(defrecord TSha512MessageDigester [msg-digest-state digest-size provider algorithm char-set]
  IFn
    (invoke [this](digest this))
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


(extend-type TSha512MessageDigester
  IMessageDigester
  (update [this bytes-or-str]
    (-update! (assoc this :msg-digest-state (aclone (:msg-digest-state this))) bytes-or-str))
  (-update! [this bytes-or-str]
    (if (coll? bytes-or-str)
      (reduce -update! this bytes-or-str)
      (let [in-bs (=>bytes bytes-or-str)
            ret (.crypto_hash_sha512_update 
                  (NaCl/sodium) 
                  (:msg-digest-state this)
                  in-bs (count in-bs))]
        (if (= ret 0)
          this
          nil))))
  (digest 
    ([this]
      (let [b-a (byte-array (:digest-size this))
            ret (.crypto_hash_sha512_final 
                  (NaCl/sodium) 
                  (aclone (:msg-digest-state this))
                  b-a)]
        (if (= ret 0)
          (->TMessageDigest b-a (:algorithm this))
          nil)))
    ([this bytes-or-str]
      (digest (update this bytes-or-str))))
  )


;; (def make-sodium-digester (partial make-message-digester :sodium))
(defmethod make-message-digester [:sodium :sha512]
  [provider function & {:keys [char-set] :as xs}]
  (let [c (if char-set char-set :utf8)
        digest-state (byte-array hash-sha512-statebytes)
        ret (.crypto_hash_sha512_init 
                   (NaCl/sodium) 
                   digest-state)]
    (if (= ret 0)
      (TSha512MessageDigester. 
        digest-state 
        hash-sha512-bytes
        :sodium 
        :sha512
        c)
      nil)))


;;;
