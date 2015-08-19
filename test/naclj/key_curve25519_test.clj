(ns naclj.key-curve25519-test
  (:require 
    [clojure.test :refer :all]
	  [naclj.encode-util :refer :all]
 	  [naclj.fixture :as f]
    [naclj.hash-sha256 :as hb]
    [naclj.hash-protocol :as h]
    [naclj.key-protocol :refer :all]
    [naclj.key-curve25519]
  ))

;;setup

;;; tests
;

(deftest curve25519-test-1
 (testing "curve25519 types"
   (is (= naclj.key_curve25519.TCurve25519KeyPair (type (make-key-pair :sodium :curve25519))))
   (is (= naclj.key_curve25519.TCurve25519PrivateKey (type (private-key (make-key-pair :sodium :curve25519)))))
   (is (= naclj.key_curve25519.TCurve25519PublicKey (type (public-key (make-key-pair :sodium :curve25519)))))
   ))


(deftest curve25519-test-2
 (testing "basic key and key-pair interface"
   (let [kp-alice (make-key-pair :sodium :curve25519)
         kp-bob   (make-key-pair :sodium :curve25519)
         sk-alice (private-key kp-alice)
         sk-bob (private-key kp-bob)
         pk-alice (public-key kp-alice)
         pk-bob (public-key kp-bob)
         kp-alice2 (make-key-pair :sodium :curve25519 :private-key sk-alice)
         kp-alice3 (key-pair sk-alice)
         ]
    (is (and (key-pair? kp-alice) (key-pair? kp-bob)))
    (is (and (public-key? pk-alice) (public-key? pk-bob)))
    (is (and (private-key? sk-alice) (private-key? sk-bob)))
    (is (and (dh-public-key? pk-alice) (dh-public-key? pk-bob)))
    (is (and (dh-private-key? sk-alice) (dh-private-key? sk-bob)))
    (is (and (pair? pk-alice sk-alice) (pair? sk-alice pk-alice)))
    (is (and (not (pair? pk-alice sk-bob)) (not (pair? sk-bob pk-alice))))
    (is (and (equal? kp-alice kp-alice2) (equal? kp-alice kp-alice3) (not (equal? kp-alice kp-bob))))
    )))

(deftest curve25519-test-3
 (testing "DH key equality"
   (let [kp-alice (make-key-pair :sodium :curve25519)
         kp-bob   (make-key-pair :sodium :curve25519)
         sk-alice (private-key kp-alice)
         sk-bob (private-key kp-bob)
         pk-alice (public-key kp-alice)
         pk-bob (public-key kp-bob)
         ]
    (is (equal? (dh-key kp-alice pk-bob) (dh-key kp-bob pk-alice)))
    )))

(deftest curve25519-test-4
 (testing "sizes and meta data"
   (let [kp-alice (make-key-pair :sodium :curve25519)
         kp-bob   (make-key-pair :sodium :curve25519)
         sk-alice (private-key kp-alice)
         sk-bob (private-key kp-bob)
         pk-alice (public-key kp-alice)
         pk-bob (public-key kp-bob)
         dh (dh-key kp-alice pk-bob)
         ]
    (is (= (key-length sk-alice) naclj.key-curve25519/curve25519-secretkeybytes))
    (is (= (key-length pk-alice) naclj.key-curve25519/curve25519-publickeybytes))
    (is (= (key-length dh) naclj.key-curve25519/curve25519-beforenmbytes))
    (is (= "curve25519" (algorithm kp-alice) (algorithm pk-alice) (algorithm sk-alice)))
    
    )))

