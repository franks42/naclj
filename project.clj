(defproject naclj "0.1.0-SNAPSHOT"
  :description "Clojure library that abstracts libsodium's crypto primitives (curve25519, ed25519, blake2b, box/unbox, sign/verify, etc.)"
  :url "https://github.com/franks42/naclj"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [
    [org.clojure/clojure "1.7.0"]
  	[com.cognitect/transit-clj "0.8.281"]
  	[com.github.jnr/jnr-ffi "2.0.3"]
  	[org.clojure/data.json "0.2.6"]
  	[org.clojure/tools.namespace "0.2.10"]
		]
	:java-source-paths ["src-java"]
  ;:dev-dependencies [[clj-ns-browser "1.3.2-SNAPSHOT"]]
  :plugins [[lein-gorilla "0.3.4"]
            ;[lein-marginalia "0.8.0"]
            ;[codox "0.8.13"]
            ]

  :main naclj.core)
