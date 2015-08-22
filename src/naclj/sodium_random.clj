(ns sodium-random
	(:import 
	  (com.github.franks42.naclj NaCl)
	  (com.github.franks42.naclj NaCl$Sodium)
    [clojure.lang IFn]
    [clojure.lang.AFn])
	(:require 
	  [naclj.key-protocol :refer :all]))

(defrecord TRandomGeneratorSodium [random-generator])

(defmethod make-random-generator :sodium [provider] 
  (map->TRandomGeneratorSodium {:random-generator :sodium}))

(extend-type TRandomGeneratorSodium
  IRandomGenerator
    (random-bytes [this n] 
      (let [bs (byte-array n)]
        (.randombytes (NaCl/sodium) bs n)
        bs))
    (random-bytes! [this bs] 
      (.randombytes (NaCl/sodium) bs (count bs))
      bs))
