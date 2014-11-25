;;;;;;;;;;;;;;;;;; UTILITY FUNCTIONS AND DEFINITIONS ;;;;;;;;;;;;;;;;;;

(load-file "util/AES-lib.clj")
(load-file "util/hash.clj")
(load-file "util/server-socket.clj")

(import java.security.SecureRandom)

;Create and seed secureRandom
(def srand (SecureRandom.))
(.nextBytes srand (byte-array 10))

;Pass in the byte-count you want
(defn large-rand-by-bytes [num-bytes]
  (let [barr  (byte-array num-bytes)]
     (.nextBytes srand barr)
     (BigInteger. barr)))

;Must pass in p as a BigInteger object
(defn large-rand [p]
  (let [num-bytes (inc (/ (.bitLength p) 8))]
      (.mod (large-rand-by-bytes num-bytes) p)))

(def HMAC-BLOCKSIZE 64)
(def HMAC-key (repeat 64 0x11))

(defn HMAC-SHA1 [key input]
   (let [buf  (sanitize-str-bytes input)
         bkey (sanitize-str-bytes key)
         lkey (if (> (count bkey) HMAC-BLOCKSIZE)
                  (DatatypeConverter/parseHexBinary (native-impl.hash/SHA1-hash bkey))
                  bkey)
         skey (let [keysize (count lkey)]
                (if (< keysize HMAC-BLOCKSIZE)
                    (concat lkey (repeat (- HMAC-BLOCKSIZE keysize) 0x00))
                    lkey))
         opad (map bit-xor (repeat HMAC-BLOCKSIZE 0x5c) skey)
         ipad (map bit-xor (repeat HMAC-BLOCKSIZE 0x36) skey)]
      (->> (native-impl.hash/SHA1-hash (concat ipad buf))
           (DatatypeConverter/parseHexBinary)
           (concat opad)
           (barray)
           (native-impl.hash/SHA1-hash))))

;;;;;;;;;;;;;;;;;; CHALLENGE 33 ;;;;;;;;;;;;;;;;;;

(def c33-p 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff)
(def c33-g 2)

(def c33-test-p 37)
(def c33-test-g 5)

(defn modexp [b e m]
  (.modPow (biginteger b) (biginteger e) (biginteger m)))

;Diffie-Hellmen key generation
;Pass in p and g, returns two sets of public/private keys and p
(defn Generate-Keypair [p g]
  (let [a (large-rand (biginteger p))]
    [(modexp g a p) a]))

(defn Diffie-Hellman [p g]
  [(Generate-Keypair p g) (Generate-Keypair p g) p])

(defn test-keys [[[A a] [B b] p]]
   (= (modexp B a p) (modexp A b p)))

;Test generating keys is correct
(defn test-challenge33 []
  (println (test-keys (Diffie-Hellman c33-test-p c33-test-g)))
  (println (test-keys (Diffie-Hellman c33-p c33-g))))

;;;;;;;;;;;;;;;;;; CHALLENGE 34 ;;;;;;;;;;;;;;;;;;

;Constants
(def c34-p 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff)
(def c34-g 2)
(def c34-secret-message "hello")

;Protocol state
(def A-keys (atom []))
(def B-keys (atom []))
(def A-p (atom (biginteger 0)))
(def B-p (atom (biginteger 0)))
(def A-public-key (atom (biginteger 0)))
(def B-public-key (atom (biginteger 0)))
;MITM server state
(def M-p (atom (biginteger 0)))

(defn c34-reset-keys []
  (reset! A-keys [])
  (reset! B-keys [])
  (reset! A-p (biginteger 0))
  (reset! B-p (biginteger 0))
  (reset! M-p (biginteger 0))
  (reset! A-public-key (biginteger 0))
  (reset! B-public-key (biginteger 0))
  true)

;Generate the message key from secret s
(defn gen-msg-key [s]
  (barray (take AES-BLOCKSIZE (.getBytes (native-impl.hash/SHA1-hash (str s))))))

;Create encrypted message and decrypt the message
;Inputs, base, exponent, prime, message
(defn encrypt-msg [s m]
  (let [IV  (barray (get-rand-bytes AES-BLOCKSIZE))
        key (gen-msg-key s)]
    [(encrypt-CBC (Pad-PKCS7-Bytes m AES-BLOCKSIZE) key IV) IV]))

(defn decrypt-msg [s [msg IV]]
  (let [key (gen-msg-key s)]
    (bytes-to-string (valid-PKCS7-Padding? (decrypt-CBC msg key IV)))))

;Protocol functions
(defn first-A-to-B [p g]
  (let [keys (Generate-Keypair c34-p c34-g)]
    (reset! A-keys keys)
    (reset! A-p p)
    [p g (first @A-keys)]))

(defn first-B-to-A [[p g A]]
  (reset! A-public-key A)
  (reset! B-p p)
  (let [keys (Generate-Keypair c34-p c34-g)]
    (reset! B-keys keys)
    (first @B-keys)))

(defn second-A-to-B [B]
  (reset! B-public-key B)
  (let [s (modexp @B-public-key (second @A-keys) @A-p)]
      (encrypt-msg s c34-secret-message)))

(defn second-B-to-A [msg-IV-pair]
  (let [s (modexp @A-public-key (second @B-keys) @B-p)]
     (encrypt-msg s (decrypt-msg s msg-IV-pair))))

(defn A-verify-last-step [msg-IV-pair]
  (let [s (modexp @B-public-key (second @A-keys) @A-p)]
    (= (decrypt-msg s msg-IV-pair) c34-secret-message)))

;MITM attack functions
;(modexp p g p) will always be 0
(defn first-M-to-B [[p g A]]
  (reset! M-p p)
  [p g p])

(defn first-M-to-A [B]
  @M-p)

(defn second-M-to-B [msg-IV-pair]
  (println "Initial message: " (decrypt-msg 0 msg-IV-pair))
  msg-IV-pair)

(defn second-M-to-A [msg-IV-pair]
  (println "Second message: " (decrypt-msg 0 msg-IV-pair))
  msg-IV-pair)

;Simulates all interactions
(defn test-challenge34 []
  (println "Do we have a proper protocol")
  (c34-reset-keys)
  (println (->> (first-A-to-B c34-p c34-g)
                (first-B-to-A)
                (second-A-to-B)
                (second-B-to-A)
                (A-verify-last-step)))
  (println "Can we do a MITM attack as specified")
  (c34-reset-keys)
  (println (->> (first-A-to-B c34-p c34-g)
                (first-M-to-B)
                (first-B-to-A)
                (first-M-to-A)
                (second-A-to-B)
                (second-M-to-B)
                (second-B-to-A)
                (second-M-to-A)
                (A-verify-last-step))))

;;;;;;;;;;;;;;;;;; CHALLENGE 35 ;;;;;;;;;;;;;;;;;;

;Reuse the same keys from challenge34

(defn send-p-g []
  (reset! A-p c34-p)
  [c34-p c34-g])

;Send back p and g in ACK
(defn send-B-ack [[p g]]
  (reset! B-p p)
  (let [keys (Generate-Keypair p g)]
    (reset! B-keys keys)
    [true p g]))

(defn send-A [[ACK p g]]
  (if ACK
    (let [keys (Generate-Keypair @A-p g)]
    (reset! A-keys keys)
    (first @A-keys))
    false))

(defn send-B [A]
   (reset! A-public-key A)
   (first @B-keys))

;Continue with second-A-to-B from here

;MITM Attack
(def g-attack-value (atom (biginteger 1)))
(defn M-send-p-g [[p g]]
  (reset! M-p p)
  [p @g-attack-value])

;Some ugly code here to test second value if first changes, but
;this is throwaway code...
(def s-attack-value (atom (biginteger 1)))
(def s-attack-value2 (atom (biginteger 1)))
(defn c35-second-M-to-B [msg-IV-pair]
  (try
    (println "Initial message: " (decrypt-msg @s-attack-value msg-IV-pair))
    (catch Exception e (println "Initial message: " (decrypt-msg @s-attack-value2 msg-IV-pair))))
  msg-IV-pair)

(defn c35-second-M-to-A [msg-IV-pair]
  (try
    (println "Second message: " (decrypt-msg @s-attack-value msg-IV-pair))
    (catch Exception e (println "Second message: " (decrypt-msg @s-attack-value2 msg-IV-pair))))
  msg-IV-pair)

(defn c35-attack
  ([g-val s-val]
    (c35-attack g-val s-val 1))
  ([g-val s-val s-val2]
  (c34-reset-keys)
  (reset! g-attack-value (biginteger g-val))
  (reset! s-attack-value (biginteger s-val))
  (reset! s-attack-value2 (biginteger s-val2))
  (println (->> (send-p-g)
                (M-send-p-g)
                (send-B-ack)
                (send-A)
                (send-B)
                (second-A-to-B)
                (c35-second-M-to-B)
                (second-B-to-A)
                (c35-second-M-to-A)
                (A-verify-last-step)))))

(defn test-challenge35 []
  (println "Do we have a proper protocol")
  (c34-reset-keys)
  (println (->> (send-p-g)
                (send-B-ack)
                (send-A)
                (send-B)
                (second-A-to-B)
                (second-B-to-A)
                (A-verify-last-step)))
  (println "Attack where G is 1?") ;S = 1
  (c35-attack 1 1)
  (println "Attack where G is p?") ;S = 0
  (c35-attack c34-p 0)
  (println "Attack where G is p-1?") ;S = 1 or p-1
  (c35-attack (dec c34-p) (dec c34-p)))

;;;;;;;;;;;;;;;;;; CHALLENGE 36 ;;;;;;;;;;;;;;;;;;

(import (java.net ServerSocket Socket SocketException)
        (java.io PrintWriter InputStreamReader BufferedReader OutputStreamWriter))

;N,G,K values we are using
(def c36-n (biginteger 0xc037c37588b4329887e61c2da3324b1ba4b81a63f9748fed2d8a410c2fc21b1232f0d3bfa024276cfd88448197aae486a63bfca7b8bf7754dfb327c7201f6fd17fd7fd74158bd31ce772c9f5f8ab584548a99a759b5a2c0532162b7b6218e8f142bce2c30d7784689a483e095e701618437913a8c39c3dd0d4ca3c500b885fe3))
(def c36-g (biginteger 2))
(def c36-k (biginteger 3))

;Other vars and constants
(def SRP-DELIM ";")
(def SRP-DELIM-REGEX (re-pattern (str "\\" SRP-DELIM)))
(def SRP-DEFAULT-PORT 3101)
(def SERVER-STORAGE (atom {}))
(def c36-DEBUG false)

;Utils
(defn write [conn msg]
  (doto (:out @conn)
    (.println (str msg "\r"))
    (.flush)))

(defn socket-write [socket msg]
  (doto socket
    (.println (str msg "\r"))
    (.flush)))

(defn hash-bigint [s]
  (BigInteger. (native-impl.hash/SHA1-hash s) 16))

(defn pack-msg [& args]
  (apply str (interleave args (repeat SRP-DELIM))))

(defn unpack-msg [msg]
  (clojure.string/split msg SRP-DELIM-REGEX))

;Server functions
(defn server-gen [password]
  (let [salt (large-rand (biginteger Integer/MAX_VALUE))
        x    (hash-bigint (str salt password))
        v    (modexp c36-g x c36-n)]
    {:salt salt :v v}))

(defn server-gen-S [A v u b]
  (modexp (.multiply A (modexp v u c36-n)) b c36-n))

(defn server-gen-B [v b]
  (.mod (.add (.multiply (biginteger v) c36-k) (modexp c36-g b c36-n)) c36-n))

(defn insert-account-into-server [email password]
  (let [vars (merge (server-gen password) {:email email :password password})]
    (swap! SERVER-STORAGE merge {(keyword email) vars})))

(defn create-SRP-server [port]
  (server.socket/create-server port
     (fn [in out]
       (binding
         [*in*  (BufferedReader. (InputStreamReader. in))
          *out* (PrintWriter. out)]
       (loop [vars (atom {})]
         (let [args     (unpack-msg (read-line))
               msg-type (first args)
               continue (atom true)
               fail-fn  (fn [msg] (do (reset! continue false)
                                  (socket-write *out* msg)))
               get-big  (fn [k] (biginteger (k @vars)))]
           (when c36-DEBUG (dosync (println "SERVER") (println vars) (println args)))
           (cond (.equalsIgnoreCase msg-type "init")
                 (do (if-let [account ((keyword (second args)) @SERVER-STORAGE)]
                       (let [key-pair (Generate-Keypair c36-n c36-g)
                             v        (:v account)
                             B        (server-gen-B v (second key-pair))
                             u        (hash-bigint (str (nth args 2) B))]
                         (swap! vars merge {:A (nth args 2) :b (second key-pair) :u u :v v :salt (str (:salt account))})
                         (socket-write *out* (pack-msg "res1" (:salt account) B)))
                       (fail-fn "ERROR: Account invalid.")))
                 (.equalsIgnoreCase msg-type "res2")
                 (let [C-K (second args)
                       S   (apply server-gen-S (for [x [:A :v :u :b]] (get-big x)))]
                   (when c36-DEBUG (dosync
                     (println "A" (:A @vars) "v" (:v @vars) "u" (:u @vars) "b" (:b @vars))
                     (println "C-K " C-K "K" (HMAC-SHA1 (:salt @vars) (str S)))))
                   (if (.equalsIgnoreCase C-K (HMAC-SHA1 (:salt @vars)  (str S)))
                       (socket-write *out* "OK")
                       (fail-fn "ERROR: Failed to authenticate")))
                 :else (fail-fn "ERROR: Invalid communication."))
       (when @continue (recur vars))))))))

;Client functions
(defn client-gen-S [B a u x]
  (modexp (.subtract B (.multiply (modexp c36-g x c36-n) c36-k))
          (.add a (.multiply u x))
          c36-n))

(defn srp-client-handler [conn vars next-fn]
  (while (nil? (:exit @conn))
    (let [args     (unpack-msg (.readLine (:in @conn)))
          msg-type (first args)]
      (when c36-DEBUG (dosync (println "CLIENT") (println args)))
      (cond
       (re-find #"^ERROR" msg-type)
       (dosync (next-fn false) (alter conn merge {:exit true}))
       (.equalsIgnoreCase "res1" msg-type)
       (let [salt (second args)
             x    (hash-bigint (str salt (:password vars)))
             B    (biginteger (nth args 2))
             u    (hash-bigint (str (:A vars) B))
             S    (client-gen-S B (:a vars) u x)
             K    (HMAC-SHA1 salt (str S))]
           (when c36-DEBUG (dosync
             (println "B" B "a" (:a vars) "u" u "x" x) (println "S " S)))
           (write conn (pack-msg "res2" K)))
       (.equalsIgnoreCase "OK" msg-type)
       (dosync (next-fn true) (alter conn merge {:exit true}))))))

(defn srp-connect [server next-fn handler]
  (let [socket (Socket. (:name server) (:port server))
        in     (BufferedReader. (InputStreamReader. (.getInputStream socket)))
        out    (PrintWriter. (.getOutputStream socket))
        conn   (ref {:in in :out out})]
    (doto (Thread. #(handler conn server next-fn))
          (.start))
    conn))

(defn srp-initiate-connection
([email password]
  (srp-initiate-connection email password "localhost" SRP-DEFAULT-PORT))
([email password server port]
  (srp-initiate-connection email password server port (Generate-Keypair c36-n c36-g) srp-client-handler))
([email password server port key-pair handler]
 (let [conn (srp-connect {:name server :port port
            :email email :password password
            :A (first key-pair) :a (second key-pair)}
            (fn [success]
             (if success (println "Successfully authenticated!")
               (println "Failed to authenticate!")))
            handler)
       conn-str (pack-msg "init" email (first key-pair))]
    (write conn conn-str))))

;Testing
(defn c36-populate-test-accounts []
  (insert-account-into-server "test" "test")
  (insert-account-into-server "hello@world.com" "pro")
  (insert-account-into-server "break@me.com" "broken"))

;To test run these in order
;(def server (create-SRP-server SRP-DEFAULT-PORT))
;(c36-populate-test-accounts)
;(srp-initiate-connection "test" "test")
;To kill server, exit lein or run ;(server.socket/close-server server)


;;;;;;;;;;;;;;;;;; CHALLENGE 37 ;;;;;;;;;;;;;;;;;;

(def c37-DEBUG false)

(def c37-attack-val (atom (str "0")))
(defn srp-attack-handler [conn vars next-fn]
  (while (nil? (:exit @conn))
    (let [args     (clojure.string/split (.readLine (:in @conn)) SRP-DELIM-REGEX)
          msg-type (first args)]
      (when c36-DEBUG (dosync (println "CLIENT") (println args)))
      (cond
       (re-find #"^ERROR" msg-type)
       (dosync (next-fn false) (alter conn merge {:exit true}))
       (.equalsIgnoreCase "res1" msg-type)
       (do (when c37-DEBUG (println "K" (HMAC-SHA1 (second args) @c37-attack-val)))
       (write conn (pack-msg "res2" (HMAC-SHA1 (second args) @c37-attack-val))))
       (.equalsIgnoreCase "OK" msg-type)
       (dosync (next-fn true) (alter conn merge {:exit true}))))))

;If A is passed as 0, then S will be 0
(defn c37-attack-0 []
  (reset! c37-attack-val "0")
  (srp-initiate-connection "test" "" "localhost" SRP-DEFAULT-PORT [(biginteger 0) (biginteger 0)] srp-attack-handler))

;If A is N, then (A * v**u) will be a multiple on N, and therefore (A * v**u) ** b % N will equal 0
(defn c37-attack-N []
  (reset! c37-attack-val "0")
  (srp-initiate-connection "test" "" "localhost" SRP-DEFAULT-PORT [c36-n c36-n] srp-attack-handler))

;If A is N^x, it will still equal 0 as S
(defn c37-attack-NPow [exp]
  (reset! c37-attack-val "0")
  (srp-initiate-connection "test" "" "localhost" SRP-DEFAULT-PORT [(.pow c36-n exp) (.pow c36-n exp)] srp-attack-handler))

(defn test-challenge37 []
  (println "Can we break SRP by sending special A values?")
  (println (and (c37-attack-0) (c37-attack-N) (c37-attack-NPow 2))))

;;;;;;;;;;;;;;;;;; CHALLENGE 38 ;;;;;;;;;;;;;;;;;;

(def c38-n (biginteger 0xc037c37588b4329887e61c2da3324b1ba4b81a63f9748fed2d8a410c2fc21b1232f0d3bfa024276cfd88448197aae486a63bfca7b8bf7754dfb327c7201f6fd17fd7fd74158bd31ce772c9f5f8ab584548a99a759b5a2c0532162b7b6218e8f142bce2c30d7784689a483e095e701618437913a8c39c3dd0d4ca3c500b885fe3))
(def c38-g (biginteger 2))
(def c38-k (biginteger 3))

;Other vars and constants
(def C-keys     (atom []))
(def S-keys     (atom []))
(def C-password (atom ""))
(def S-A        (atom (biginteger 0)))
(def S-email    (atom ""))
(def S-u        (atom (biginteger 0)))

(def c38-auth-error "Error: Failed to authenticate")

;Generate some static values for testing
(def c38-email    "test")
(def c38-password "test")
(def salt         (large-rand c38-n))
(def c38-x        (hash-bigint (str salt c38-password)))
(def c38-v        (modexp c38-g c38-x c38-n))

;Stub functions that would be replaced in real impl.
(defn email-exists? [email]
  (.equalsIgnoreCase email c38-email))

(defn get-x-v-salt [email]
  (if (.equalsIgnoreCase email c38-email)
      [c38-x c38-v salt]
      nil))

(defn check-error [input]
  (if (.equalsIgnoreCase c38-auth-error input)
      (throw (Exception. c38-auth-error))
      input))

;Protocol functions
(defn C->S1 [[email password]]
   (reset! C-keys (Generate-Keypair c38-n c38-g))
   (reset! C-password password)
   (pack-msg email (first @C-keys)))

(defn S->C1 [input]
  (let [[email A] (unpack-msg input)]
  (if (email-exists? email)
    (do (reset! S-keys (Generate-Keypair c38-n c38-g))
        (reset! S-u (large-rand-by-bytes 16))
        (reset! S-A (biginteger A))
        (reset! S-email email)
        (pack-msg salt (first @S-keys) @S-u))
    c38-auth-error)))

(defn C->S2 [input]
  (let [[salt B u] (map biginteger (unpack-msg input))
        x          (hash-bigint (str salt @C-password))
        S          (modexp B (.add (second @C-keys) (.multiply x u)) c38-n)]
    (HMAC-SHA1 (str salt) (str S))))

(defn S->C2 [C-K]
  (let [[x v salt] (get-x-v-salt @S-email)
        base  (.multiply @S-A (modexp v @S-u c38-n))
        S     (modexp base (second @S-keys) c38-n)
        K     (HMAC-SHA1 (str salt) (str S))]
    (if (.equalsIgnoreCase C-K K) "OK" c38-auth-error)))

;MITM functions
;Return salt as 0,
(defn C->M1 [input]

)


(defn test-challenge38 []
  (println "Do we have a proper protocol")
  (println (-> ["test" "test"]
            (C->S1)
            (S->C1)
            (check-error)
            (C->S2)
            (S->C2)))
  (println "Can we break it?"))

;;;;;;;;;;;;;;;;;; CHALLENGE 39 ;;;;;;;;;;;;;;;;;;

(def c39-p (biginteger 491))
(def c39-q (biginteger 857))
(def c39-e (biginteger 3))

;All inputs should be big integers
;Can fail if gcd e and et is not = 1
(defn gen-RSA-keys-unsafe
([] (gen-RSA-keys-unsafe (BigInteger/probablePrime 1024 srand)
                         (BigInteger/probablePrime 1024 srand)
                         c39-e))
([p q e]
(let [n  (.multiply p q)
      et (.multiply (.subtract p (biginteger 1)) (.subtract q (biginteger 1)))
      d  (.modInverse e et)]
  [[e n][d n]])))

;Will repeatedly call the unsafe RSA function until valid keys are generated
(defn gen-RSA-keys []
  (loop []
    (if-let [success (try (gen-RSA-keys-unsafe)
                          (catch Exception e false))]
      (do (println success) success)
      (recur))))

(defn encrypt-RSA [[e n] msg]
  (let [msg-val (biginteger (.getBytes msg))]
    (modexp msg-val e n)))

(defn decrypt-RSA [[d n] msg]
  (let [decrypt-val (String. (.toByteArray (modexp msg d n)))]
    decrypt-val))

(defn test-challenge39 []
  (println "Do we have a proper RSA implementation?")
  (println "Attempting to encrypt/decrypt string: supersecret")
  (println "Decrypted as:"
           (let [RSA-keys (gen-RSA-keys)]
               (decrypt-RSA (second RSA-keys)
                            (encrypt-RSA (first RSA-keys) "supersecret")))))

;;;;;;;;;;;;;;;;;; CHALLENGE 40 ;;;;;;;;;;;;;;;;;;

(def c40-secret "This is a rather boring supersecret")

(defn gen-ciphertext-pubkey [secret]
  (let [RSA-keys (gen-RSA-keys)
        pubkeys  (first RSA-keys)]
      [(encrypt-RSA pubkeys secret) pubkeys]))

(def break-vals (take 3 (repeatedly #(gen-ciphertext-pubkey c40-secret))))

(defn break-RSA-3 [inputs]
  (let [ciphertexts (map first inputs)
        n_vals      (map #(second (second %)) inputs)
        m_s_vals    [(.multiply (second n_vals) (nth n_vals 2))
                     (.multiply (first n_vals) (nth n_vals 2))
                     (.multiply (first n_vals) (second n_vals))]
        invmods     (map #(.modInverse %1 %2) m_s_vals n_vals)]
      (reduce (fn [x y] (.add x y)) (map #(.multiply (.multiply %1 %2) %3) ciphertexts n_vals invmods))))

(def big2 (biginteger 2))
(def big1 (biginteger 1))
(defn b> [b1 b2] (> 0 (.compareTo b2 b1)))
(defn b< [b1 b2] (< 0 (.compareTo b2 b1)))

;Find nth root using binary search
(defn nth-root [n root]
  (let [upper-bound (loop [res big1]
                    (if (b> (.pow res root) n) res (recur (.multiply res big2))))
        lower-bound (.divide upper-bound big2)]
   (loop [high upper-bound low lower-bound]
     (let [mid (.divide (.add high low) big2)]
       (if (b< low high)
           (cond (and (b< low mid) (b< (.pow mid root) n))
                 (recur high mid)
                 (and (b> high mid) (b> (.pow mid root) n))
                 (recur mid low)
                 :else mid)
           (.add mid big1))))))