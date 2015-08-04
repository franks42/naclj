(defproject naclj "0.1.0-SNAPSHOT"
  :description "Clojure library that abstracts libsodium's crypto primitives (curve25519, ed25519, blake2b, box/unbox, sign/verify, etc.)"
  :url "https://github.com/franks42/naclj"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [
    [org.clojure/clojure "1.7.0"]
    [org.clojure/tools.namespace "0.2.10"]
    [clj-ns-browser "1.3.2-SNAPSHOT"]
  	[commons-codec/commons-codec "1.10"]
  	[com.cognitect/transit-clj "0.8.275"]
  	[com.github.jnr/jnr-ffi "2.0.3"]
		]
	:java-source-paths ["src-java"]
  :main naclj.core)
