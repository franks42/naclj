(ns naclj.hash-sha512-test
  (:require 
    [clojure.test :refer :all]
	  [clojure.tools.namespace.repl :refer [refresh]]
	  [naclj.encode-util :refer :all]
 	  [naclj.fixture :as f]
    [naclj.hash-sha512 :as hb]
    [naclj.hash-protocol :as h]
  ))

;;setup

;;; tests
;

(deftest hash-test-1
 (testing "create digester"
   (is (= naclj.hash_sha512.TSha512MessageDigester (type (h/make-message-digester :sodium :sha512))))

   )  
 )


(deftest hash-test-2
 (testing "test empty string"
   (let [md (h/make-message-digester :sodium :sha512)]
    (is (= f/SHA512_DIGEST_EMPTY_STRING (=>hex-str (h/digest md))))
    (is (= f/SHA512_DIGEST_EMPTY_STRING (=>hex-str (h/digest md ""))))
    (is (= f/SHA512_DIGEST_EMPTY_STRING 
           (=>hex-str (h/digest (h/make-message-digester :sodium :sha512) ""))))
    )))

(deftest hash-test-3
 (testing "test foxy string: 'My Bonnie lies over the ocean, Oh bring back my Bonnie to me'"
   (let [md (h/make-message-digester :sodium :sha512)]
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest md (=>bytes f/SHA512_MESSAGE)))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest md f/SHA512_MESSAGE))))
    (is (= f/SHA512_DIGEST 
           (=>hex-str (h/digest (h/make-message-digester :sodium :sha512) f/SHA512_MESSAGE))))
    )))

(deftest hash-test-4
 (testing "test incremental foxy string: 'My Bonnie lies over the ocean, Oh bring back my Bonnie to me'"
   (let [md (h/make-message-digester :sodium :sha512)]
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest md "My Bonnie lies over the ocean, Oh bring back my Bonnie to me"))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest (h/update md "My Bonnie lies over the ocean, Oh bring back my Bonnie to me")))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest (h/update (h/update md "My Bonnie lies over the ocean,") " Oh bring back my Bonnie to me")))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest (h/update (h/update md "My Bonnie lies over the ocean,") " Oh bring back ") "my Bonnie to me"))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest (reduce h/update md ["My Bonnie lies over the ocean," " Oh bring back " "my Bonnie to me"])))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest (reduce h/update md ["My Bonnie lies over the ocean," (=>bytes " Oh bring back ") "my Bonnie to me"])))))
    )))

(deftest hash-test-5
 (testing "test incremental foxy string over collections: 'My Bonnie lies over the ocean, Oh bring back my Bonnie to me'"
   (let [md (h/make-message-digester :sodium :sha512)]
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest md "My Bonnie lies over the ocean, Oh bring back my Bonnie to me"))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest md ["My Bonnie lies over the ocean, Oh bring back my Bonnie to me"]))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest md '(["My Bonnie lies over the ocean,"] [" Oh bring back my Bonnie to me"])))))
    (is (= f/SHA512_DIGEST (=>hex-str (h/digest md '(["My Bonnie lies over " ["the ocean,"]] [" Oh bring back my Bonnie to me"])))))
    )))

(deftest hash-test-6
 (testing "test digester as a function interface"
   (let [md (h/make-message-digester :sodium :sha512)]
    (is (= f/SHA512_DIGEST (=>hex-str (md "My Bonnie lies over the ocean, Oh bring back my Bonnie to me"))))
    (is (= f/SHA512_DIGEST (=>hex-str ((h/make-message-digester :sodium :sha512) "My Bonnie lies over the ocean, Oh bring back my Bonnie to me"))))
    (is (= f/SHA512_DIGEST (=>hex-str ((h/make-message-digester :sodium :sha512) "My Bonnie lies over the ocean," " Oh bring back my Bonnie to me"))))    
    )))
