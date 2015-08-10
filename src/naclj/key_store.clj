(ns naclj.key-store)

(def the-key-store (atom {}))

;(defn make-keystore [owner]
;  (assoc the-key-store owner))
  
(defn add-key [owner key value]
  (swap! the-key-store assoc-in [owner key] value))
  
(defn get-key [owner key]
  (get-in @the-key-store [owner key]))
