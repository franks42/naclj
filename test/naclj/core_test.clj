(ns naclj.core-test
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
	  (org.apache.commons.codec.binary)
    )
  (:require 
    [clojure.test :refer :all]
	  [clojure.tools.namespace.repl :refer [refresh]]
	  [naclj.protocol :refer :all]
	  [naclj.encode-util :refer :all]
 	  [naclj.fixture :as f]
    [naclj.core :refer :all]))

;;setup

(deftest tttt
 (testing "private and public key getters"
   (is (not= 1 0))))


;(def kp (make-key-pair2))
;
;;; tests
;
;(deftest key-pair-test-1
;  (testing "private and public key ?"
;    (is (= true (key-pair? kp)))
;    (is (= true (public-key? (public-key kp))))
;    (is (= true (private-key? (private-key kp))))
;    (is (= true (pair? (public-key kp) (private-key kp))))
;    )  
;  )
;
;(deftest key-test-2
;  (testing "private and public key getters"
;    (is (not= (.getPublicKey kp) (public-key kp)))
;    (is (not= (.getPrivateKey kp) (private-key kp)))
;    (is (equal? (.getPublicKey kp) (public-key kp)))
;    (is (equal? (.getPrivateKey kp) (private-key kp)))
;    )  
;  )
;
;(deftest key-pair-3
;  (testing "pair from private raw key"
;    (let [kp2 (make-key-pair2 f/BOB_PRIVATE_KEY)
;          kp3 (make-key-pair2 (=>bytes f/BOB_PRIVATE_KEY))]
;      (is (= true (key-pair? kp2)))
;      (is (= f/BOB_PRIVATE_KEY (str (private-key kp2))))
;      (is (= f/BOB_PUBLIC_KEY (str (public-key kp2))))
;      (is (= true (key-pair? kp3)))
;      (is (= f/BOB_PRIVATE_KEY (str (private-key kp3))))
;      (is (= f/BOB_PUBLIC_KEY (str (public-key kp3))))
;      (is (not= (=>bytes f/BOB_PRIVATE_KEY) (=>bytes (private-key kp3))))
;      (is (equal? (=>bytes f/BOB_PRIVATE_KEY) (=>bytes (private-key kp3))))
;      (is (not= (=>bytes f/BOB_PUBLIC_KEY) (=>bytes (public-key kp3))))
;      (is (equal? (=>bytes f/BOB_PUBLIC_KEY) (=>bytes (public-key kp3))))
;    )) 
;  )
