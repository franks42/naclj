(ns naclj.hash-sha256-test
  (:require 
    [clojure.test :refer :all]
	  [naclj.encode-util :refer :all]
 	  [naclj.fixture :as f]
    [naclj.hash-sha256 :as hb]
    [naclj.hash-protocol :as h]
  ))

;;setup

;;; tests
;

(deftest hash-test-1
 (testing "create digester"
   (is (= naclj.hash_sha256.TSha256MessageDigester (type (h/make-message-digester :sodium :sha256))))

   )  
 )


(deftest hash-test-2
 (testing "test empty string"
   (let [md (h/make-message-digester :sodium :sha256)]
    (is (= f/SHA256_DIGEST_EMPTY_STRING (=>hex-str (h/digest md))))
    (is (= f/SHA256_DIGEST_EMPTY_STRING (=>hex-str (h/digest md ""))))
    (is (= f/SHA256_DIGEST_EMPTY_STRING 
           (=>hex-str (h/digest (h/make-message-digester :sodium :sha256) ""))))
    )))

(deftest hash-test-3
 (testing "test foxy string: 'My Bonnie lies over the ocean, my Bonnie lies over the sea'"
   (let [md (h/make-message-digester :sodium :sha256)]
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest md (=>bytes f/SHA256_MESSAGE)))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest md f/SHA256_MESSAGE))))
    (is (= f/SHA256_DIGEST 
           (=>hex-str (h/digest (h/make-message-digester :sodium :sha256) f/SHA256_MESSAGE))))
    )))

(deftest hash-test-4
 (testing "test incremental foxy string: 'My Bonnie lies over the ocean, my Bonnie lies over the sea'"
   (let [md (h/make-message-digester :sodium :sha256)]
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest md "My Bonnie lies over the ocean, my Bonnie lies over the sea"))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest (h/update md "My Bonnie lies over the ocean, my Bonnie lies over the sea")))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest (h/update (h/update md "My Bonnie lies over the ocean,") " my Bonnie lies over the sea")))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest (h/update (h/update md "My Bonnie lies over the ocean,") " my Bonnie lies") " over the sea"))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest (reduce h/update md ["My Bonnie lies over the ocean," " my Bonnie lies" " over the sea"])))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest (reduce h/update md ["My Bonnie lies over the ocean," (=>bytes " my Bonnie lies") " over the sea"])))))
    )))

(deftest hash-test-5
 (testing "test incremental foxy string over collections: 'My Bonnie lies over the ocean, my Bonnie lies over the sea'"
   (let [md (h/make-message-digester :sodium :sha256)]
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest md "My Bonnie lies over the ocean, my Bonnie lies over the sea"))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest md ["My Bonnie lies over the ocean, my Bonnie lies over the sea"]))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest md '(["My Bonnie lies over the ocean,"] [" my Bonnie lies over the sea"])))))
    (is (= f/SHA256_DIGEST (=>hex-str (h/digest md '(["My Bonnie lies over " ["the ocean,"]] [" my Bonnie lies over the sea"])))))
    )))

(deftest hash-test-6
 (testing "test digester as a function interface"
   (let [md (h/make-message-digester :sodium :sha256)]
    (is (= f/SHA256_DIGEST (=>hex-str (md "My Bonnie lies over the ocean, my Bonnie lies over the sea"))))
    (is (= f/SHA256_DIGEST (=>hex-str ((h/make-message-digester :sodium :sha256) "My Bonnie lies over the ocean, my Bonnie lies over the sea"))))
    (is (= f/SHA256_DIGEST (=>hex-str ((h/make-message-digester :sodium :sha256) "My Bonnie lies over the ocean," " my Bonnie lies over the sea"))))    
    )))
