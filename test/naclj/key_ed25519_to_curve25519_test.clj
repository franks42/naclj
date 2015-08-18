(ns naclj.key-ed25519-to-curve25519-test
  (:require 
    [clojure.test :refer :all]
	  [naclj.encode-util :refer :all]
 	  [naclj.fixture :as f]
    [naclj.hash-sha256 :as hb]
    [naclj.hash-protocol :as h]
    [naclj.key-protocol :as kp]
    [naclj.key-curve25519]
    [naclj.key-ed25519-to-curve25519]
  ))

;;setup

;;; tests
;

(deftest key-ed25519-to-curve25519-test-1
  (testing "conversion and whether result is key-pair or not"
    (let [ed-kp-a (kp/make-key-pair :sodium :ed25519)
          c-pk-a (kp/curve25519-public-key ed-kp-a)
          c-sk-a (kp/curve25519-private-key ed-kp-a)]
      (is (= (type c-pk-a) naclj.key_curve25519.TCurve25519PublicKey))
      (is (= (type c-sk-a) naclj.key_curve25519.TCurve25519PrivateKey))
      (is (kp/pair? c-pk-a c-sk-a)))))
