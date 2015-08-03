(defproject naclj "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [
    [org.clojure/clojure "1.6.0"]
    [org.clojure/tools.namespace "0.2.10"]
    [clj-ns-browser "1.3.2-SNAPSHOT"]
  	[org.clojars.franks42/clj.security.message-digest "0.1.0-SNAPSHOT"]
  	;[org.abstractj.kalium/kalium "0.3.1-SNAPSHOT"]
  	[commons-codec/commons-codec "1.10"]
  	[com.cognitect/transit-clj "0.8.275"]
  	[com.github.jnr/jnr-ffi "2.0.3"]
		]
	:java-source-paths ["src-java"]
  :main naclj.core)
