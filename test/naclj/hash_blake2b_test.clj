(ns naclj.hash-blake2b-test
  (:require 
    [clojure.test :refer :all]
	  [naclj.encode-util :refer :all]
 	  [naclj.fixture :as f]
    [naclj.hash-blake2b :as hb]
    [naclj.hash-protocol :as h]
  ))

;;setup

;;; tests
;

(deftest hash-test-1
 (testing "create digester"
   (is (= naclj.hash_blake2b.TBlake2bMessageDigester (type (h/make-message-digester :sodium :blake2b :digest-size :max))))

   )  
 )


(deftest hash-test-2
 (testing "test empty string"
   (let [md (h/make-message-digester :sodium :blake2b :digest-size :max)]
    (is (= f/Blake2_DIGEST_EMPTY_STRING (=>hex-str (h/digest md))))
    (is (= f/Blake2_DIGEST_EMPTY_STRING (=>hex-str (h/digest md ""))))
    (is (= f/Blake2_DIGEST_EMPTY_STRING 
           (=>hex-str (h/digest (h/make-message-digester :sodium :blake2b :digest-size :max) ""))))
    )))

(deftest hash-test-3
 (testing "test foxy string: 'The quick brown fox jumps over the lazy dog'"
   (let [md (h/make-message-digester :sodium :blake2b :digest-size :max)]
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest md (=>bytes f/Blake2_MESSAGE)))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest md f/Blake2_MESSAGE))))
    (is (= f/Blake2_DIGEST 
           (=>hex-str (h/digest (h/make-message-digester :sodium :blake2b :digest-size :max) f/Blake2_MESSAGE))))
    )))

(deftest hash-test-4
 (testing "test incremental foxy string: 'The quick brown fox jumps over the lazy dog'"
   (let [md (h/make-message-digester :sodium :blake2b :digest-size :max)]
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest md "The quick brown fox jumps over the lazy dog"))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest (h/update md "The quick brown fox jumps over the lazy dog")))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest (h/update (h/update md "The quick brown fox jumps over the") " lazy dog")))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest (h/update (h/update md "The quick brown fox jumps") " over the") " lazy dog"))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest (reduce h/update md ["The quick brown fox jumps" " over the" " lazy dog"])))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest (reduce h/update md ["The quick brown fox jumps" (=>bytes " over the") " lazy dog"])))))
    )))

(deftest hash-test-5
 (testing "test incremental foxy string over collections: 'The quick brown fox jumps over the lazy dog'"
   (let [md (h/make-message-digester :sodium :blake2b :digest-size :max)]
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest md "The quick brown fox jumps over the lazy dog"))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest md ["The quick brown fox jumps over the lazy dog"]))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest md '(["The quick brown "] ["fox jumps over the lazy dog"])))))
    (is (= f/Blake2_DIGEST (=>hex-str (h/digest md '(["The quick" [" brown "]] ["fox jumps over the lazy dog"])))))
    )))

(deftest hash-test-6
 (testing "test digester as a function interface"
   (let [md (h/make-message-digester :sodium :blake2b :digest-size :max)]
    (is (= f/Blake2_DIGEST (=>hex-str (md "The quick brown fox jumps over the lazy dog"))))
    (is (= f/Blake2_DIGEST (=>hex-str ((h/make-message-digester :sodium :blake2b :digest-size :max) "The quick brown fox jumps over the lazy dog"))))
    (is (= f/Blake2_DIGEST (=>hex-str ((h/make-message-digester :sodium :blake2b :digest-size :max) "The quick brown fox " "jumps over the lazy dog"))))    
    )))
  
(deftest hash-test-7
 (testing "test with key, salt and personal: 'The quick brown fox jumps over the lazy dog'"
    (is (= f/Blake2_DIGEST_WITH_SALT_PERSONAL
           (=>hex-str (h/digest (h/make-message-digester :sodium :blake2b 
                                  :digest-size :max
                                  :key (=>bytes f/Blake2_KEY) 
                                  :salt (=>bytes f/Blake2_SALT) 
                                  :personal (=>bytes f/Blake2_PERSONAL))  
                        f/Blake2_MESSAGE))))))
           
           