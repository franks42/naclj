(ns naclj.uri-util-test
  (:require 
    [clojure.test :refer :all]
	  [naclj.uri-util :refer :all]
  ))

;;setup

;;; tests
;

(deftest urn-test-1
 (testing "urn"
   (is (= (urn? (java.net.URI. "urn:abc:def:xyz")) true)
   )))


(deftest urn-test-2
 (testing "urn's"
   (let [u "urn:abc:def:xyz"]
    (is (= (urn? u) true))
    (is (= (urn-ns u) "abc"))
    (is (= (urn-ns-string u) "xyz"))
    (is (= (urn-ns+subns u) ["abc" "def"]))
    (is (= (urn-ns+subns+string u) ["abc" "def" "xyz"]))
    )))
