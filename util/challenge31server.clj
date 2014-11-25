;This is the server for challenge 31. Was created under a project called hello-world...

(ns hello-world.handler
  (:use compojure.core hello-world.hash)
  (:import javax.xml.bind.DatatypeConverter)
  (:require [compojure.handler :as handler]
            [compojure.route :as route]))

(def HMAC-BLOCKSIZE 64)
(def HMAC-key (repeat 64 0x11))
(def BYTE-DELAY 50)
(def BYTE-DELAY2 5)

(defn read-file-into-buffer [f] (clojure.string/replace (slurp f) #"\n" ""))

(defn HMAC-SHA1 [key input]
   (let [buf  (sanitize-str-bytes input)
         bkey (sanitize-str-bytes key)
         lkey (if (> (count bkey) HMAC-BLOCKSIZE)
                  (DatatypeConverter/parseHexBinary (SHA1-hash bkey))
                  bkey)
         skey (let [keysize (count lkey)]
                (if (< keysize HMAC-BLOCKSIZE)
                    (concat lkey (repeat (- HMAC-BLOCKSIZE keysize) 0x00))
                    lkey))
         opad (map bit-xor (repeat HMAC-BLOCKSIZE 0x5c) skey)
         ipad (map bit-xor (repeat HMAC-BLOCKSIZE 0x36) skey)]
      (->> (SHA1-hash (concat ipad buf))
           (DatatypeConverter/parseHexBinary)
           (concat opad)
           (barray)
           (SHA1-hash))))

(defn test-HMAC []
  (println "Do we have a proper SHA1-HMAC?")
  (println (every? true? [(= (HMAC-SHA1 "" "") "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
                          (= (HMAC-SHA1 "key" "The quick brown fox jumps over the lazy dog") "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")])))

;insecure_compare function as described in the challenge
;assumes the signatures are of equal length
(defn insecure_compare [sig1 sig2 sleep-delay]
  (let [[s1 s2] [(DatatypeConverter/parseHexBinary sig1)
                 (DatatypeConverter/parseHexBinary sig2)]]
    (loop [s1 s1 s2 s2]
      (cond (empty? s1) true
            (= (first s1) (first s2)) (do (Thread/sleep sleep-delay)
                                          (recur (rest s1) (rest s2)))
            :else false))))

;secure_compare I wrote just for reference
;Trick is to bit-xor bytes
(defn secure_compare [sig1 sig2]
  (let [[s1 s2] [(DatatypeConverter/parseHexBinary sig1)
             (DatatypeConverter/parseHexBinary sig2)]]
     (= 0 (reduce bit-or (map bit-xor s1 s2)))))

(defn HMAC-handler [file signature sleep-delay]
   (let [local-sig (HMAC-SHA1 HMAC-key (read-file-into-buffer file))]
     (if (and (= (count signature) (count local-sig))
              (insecure_compare local-sig signature sleep-delay))
         {:status 200 :body "Valid signature"}
         {:status 500})))

(defroutes app-routes
  (GET "/" [] (concat (SHA1-hash "") "<br>" (HMAC-SHA1 "key" "The quick brown fox jumps over the lazy dog")))
  (GET "/test/:file/:signature" [file signature] (HMAC-handler file signature BYTE-DELAY))
  (GET "/test2/:file/:signature" [file signature] (HMAC-handler file signature BYTE-DELAY2))
  (GET "/verify/:file" [file] (HMAC-SHA1 HMAC-key (read-file-into-buffer file)))
  (route/resources "/")
  (route/not-found "Not Found"))

(def app
  (handler/site app-routes))
