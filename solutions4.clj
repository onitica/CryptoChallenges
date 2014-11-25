;;;;;;;;;;;;;;;;;; UTILITY FUNCTIONS AND DEFINITIONS ;;;;;;;;;;;;;;;;;;

(load-file "util/AES-lib.clj")

(defn read-file-into-buffer [f] (clojure.string/replace (slurp f) #"\n" ""))

;;;;;;;;;;;;;;;;;; CHALLENGE 25 ;;;;;;;;;;;;;;;;;;

(def c25-str (bytes-to-string (valid-PKCS7-Padding? (decrypt-ECB (base64-to-bytes (read-file-into-buffer "text/challenge7.txt")) "YELLOW SUBMARINE"))))
(def c25-key (get-rand-bytes AES-BLOCKSIZE))
(def c25-encrypted-CTR (encrypt-CTR c25-str c25-key EMPTY-NONCE))

;Splice new into old at start location
(defn splice-in [old new start]
	(let [end (+ (count new) start)]
	(concat (take start old) new (drop end old))))

;Edit CTR function
(defn edit-CTR [ciphertext key offset newtext]
	(let [block-offset        (quot offset AES-BLOCKSIZE)
		  inner-offset        (- offset (* block-offset AES-BLOCKSIZE))
		  text-block-count    (int (Math/ceil (/ (count newtext) AES-BLOCKSIZE)))
		  total-block-count   (+ 2 text-block-count)
		  keystream           (concat-bytes-to-array (take total-block-count (CTR-keystream key (long-to-le-bytes EMPTY-NONCE) block-offset)))
		  decrypted-bytes     (bit-xor-blocks keystream (drop (* AES-BLOCKSIZE block-offset) ciphertext))
          replaced-bytes      (splice-in decrypted-bytes (.getBytes newtext "UTF-8") inner-offset)
		  re-encrypted-bytes  (bit-xor-blocks replaced-bytes keystream)]
		(barray (splice-in ciphertext re-encrypted-bytes (* AES-BLOCKSIZE block-offset)))))

(defn hidden-key-edit-CTR [ciphertext offset newtext]
	(edit-CTR ciphertext c25-key offset newtext))

;I simply replace the whole edit-text with chosen bytes and then compare the output the ciphertext, when they are exactly the same I have the plain text
(defn c25-decrypt-edit-CTR [ciphertext edit-fn]
	(loop [found-text (repeat (count ciphertext) 0)]
		(let [re-edit (edit-fn ciphertext 0 (bytes-to-string found-text))]
		(if (every? true? (map #(= %1 %2) re-edit ciphertext))
			(bytes-to-string found-text)
			(recur (map #(if (= %1 %2) %3 (inc %3)) re-edit ciphertext found-text))))))

(defn test-challenge25 []
	(println "Testing challenge 25:")
	(println "Do we have a proper edit-text function.")
	(println (let [rand-offset         (rand-int 300)
				   test-str            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				   replaced-ciphertext (bytes-to-string (decrypt-CTR (edit-CTR c25-encrypted-CTR c25-key rand-offset test-str) c25-key EMPTY-NONCE))]
				(= test-str (apply str (take (count test-str) (drop rand-offset replaced-ciphertext))))))
	(println "Can we decrypt the plaintext using the CTR edit function?")
	(println (= c25-str (c25-decrypt-edit-CTR c25-encrypted-CTR hidden-key-edit-CTR))))

;;;;;;;;;;;;;;;;;; CHALLENGE 26 ;;;;;;;;;;;;;;;;;;

(def prepend-data "comment1=cooking%20MCs;userdata=")
(def append-data ";comment2=%20like%20a%20pound%20of%20bacon")
(def c26-key (get-rand-bytes AES-BLOCKSIZE))

;Modified functions from challenge 16 to use CTR instead
(defn create-data-str [s]
	(str prepend-data
		 (-> s (clojure.string/replace #";" "%3B") (clojure.string/replace #"=" "%3D"))
		 append-data))

(defn c26-create-encrypted-msg [s]
	(-> (create-data-str s)
		(encrypt-CTR c26-key EMPTY-NONCE)))

(defn c26-decrypt-msg [s]
	(bytes-to-string (decrypt-CTR s c26-key EMPTY-NONCE)))

(defn admin-check [s]
	(.contains s ";admin=true;"))

;Trick here is to pass in a string of all 0's to the encryption function - this will make it so the decryption function really passes us the keystream for those bytes
;After we have a keystream block, all we need to do is replace it with the keystream block xored with our attack string's bytes

(def c26-injection-msg "blues;admin=true")
(def c26-injection-point (count prepend-data))

;Pass in the encryption function, the string to inject, and the location in the keystream to inject it
(defn alter-CTR-keystream [encryption-fn str-to-inject insertion-point]
	(let [injection-count (count str-to-inject)
		  ciphertext      (c26-create-encrypted-msg (bytes-to-string (repeat injection-count 0)))
		  keystream-block (take injection-count (drop insertion-point ciphertext))]
		(barray (splice-in ciphertext (bit-xor-blocks (.getBytes str-to-inject "UTF-8") keystream-block) insertion-point))))

(defn test-challenge26 []
	(println "Testing challenge 26:")
	(println "Can we create an altered ciphertext that contains ;admin=true;")
	(println (admin-check (c26-decrypt-msg (alter-CTR-keystream c26-create-encrypted-msg c26-injection-msg c26-injection-point)))))

;;;;;;;;;;;;;;;;;; CHALLENGE 27 ;;;;;;;;;;;;;;;;;;

;We are exposing the IV in this challenge, since P'_1 XOR P'_3 is really equivalent to IV XOR C1 XOR C1, which equals the IV (which is equal to the key in this challenge)

(def c27-key (get-rand-bytes AES-BLOCKSIZE))

(defn c27-create-encrypted-message [s]
	(encrypt-CBC (sanitize-str-bytes s) c27-key c27-key))

(defn c27-decrypt-message [s]
	(barray (decrypt-CBC s c27-key c27-key)))

;Checks for any high ascii characters (i.e. first bit is used)
(defn compliant-ascii [buf]
	(every? (partial = 0) (map (partial bit-and 0x80) buf)))

;Returns true if the message is compliant, otherwise returns the plaintext bytes
(defn c27-server-response [encrypted-msg]
	(let [decrypted-bytes (c27-decrypt-message encrypted-msg)]
		(if (compliant-ascii decrypted-bytes) true
			decrypted-bytes)))

(defn c27-determine-key [message-encryption-fn server-fn]
	(let [msg                   "Four score and seven years ago our fathers broug"
		  ciphertext            (message-encryption-fn msg)
		  modified-ciphertext   (let [first-block (take 16 ciphertext)] (concat-bytes-to-array [first-block (repeat AES-BLOCKSIZE 0) first-block]))
		  server-response-bytes (server-fn modified-ciphertext)]
		(bit-xor-blocks (take AES-BLOCKSIZE server-response-bytes) (take AES-BLOCKSIZE (drop (* 2 AES-BLOCKSIZE) server-response-bytes)))))

(defn test-challenge27 []
	(println "Testing challenge 27:")
	(println "Can we determine the key based on the following conditions: server key and IV is the same, and server returns plaintext bytes even if decryption is invalid?")
	(println (= (seq c27-key) (seq (c27-determine-key c27-create-encrypted-message c27-server-response)))))


;;;;;;;;;;;;;;;;;; CHALLENGE 28 ;;;;;;;;;;;;;;;;;;

;Constants defined for SHA1-hash
(def h0 0x67452301)
(def h1 0xEFCDAB89)
(def h2 0x98BADCFE)
(def h3 0x10325476)
(def h4 0xC3D2E1F0)

;Unsigned right shift operator
(defn >>> [^Integer v ^Short bits] (bit-shift-right (bit-and 0xFFFFFFFF v) bits))

;Assumes 32-bit word size, super inefficient but clojure doesn't have good syntax for this
(defn left-rotate [^Integer w ^Integer shift] (bit-and (bit-xor (bit-shift-left w shift) (>>> w (- 32 shift))) 0xFFFFFFFF))

;Conversion function between primitives and bytes
(defn #^bytes long-to-bytes
  ([^long n] (long-to-bytes n ByteOrder/BIG_ENDIAN))
  ([^long n byte-order]
	(-> (ByteBuffer/allocate 8)
		(.order byte-order)
		(.putLong (.longValue n))
		(.array))))

(defn #^bytes int-to-bytes
  ([^Integer n] (int-to-bytes n ByteOrder/BIG_ENDIAN))
  ([^Integer n byte-order]
	(-> (ByteBuffer/allocate 4)
		(.order byte-order)
		(.putInt (.intValue n))
		(.array))))

(defn ^Integer bytes-to-int
  ([#^bytes n] (bytes-to-int n ByteOrder/BIG_ENDIAN))
  ([#^bytes n byte-order]
	(-> (ByteBuffer/wrap n)
		(.order byte-order)
		(.getInt))))

(defn ^Long bytes-to-long
  ([#^bytes n] (bytes-to-long n ByteOrder/BIG_ENDIAN))
  ([#^bytes n byte-order]
	(-> (ByteBuffer/wrap n)
		(.order byte-order)
		(.getLong))))

;Inefficient and barely tested implementation of SHA1 in Clojure, made by yours truly

;Determine padding with Merkle-Damgard construction
;Pads to 512-bit blocks
;Pass in count of bytes in the original message
;The byte-order passed in determines the byte order of the length padding added
(defn hash-padding [buf-count byte-order]
	(let [bit-pad-length (let [diff (mod buf-count 64)]
							   (cond (= diff 0) 56
									 (>= diff 56) (+ 64 (- 56 diff))
									 :else (- 56 diff)))
		 bytes-to-pad (conj (repeat (dec bit-pad-length) 0) -128)]
	(concat bytes-to-pad (long-to-bytes (* 8 buf-count) byte-order))))

;Function to pad the SHA-1 input to a multiple of 512 bits (or 64 bytes)
;AKA Preprocess block on Wikipedia
(defn SHA1-preprocess [buf]
	(let [buf-bytes (sanitize-str-bytes buf)]
	(concat buf-bytes (hash-padding (count buf-bytes) ByteOrder/BIG_ENDIAN))))

;Extend the sixteen 32-bit words into eighty 32-bit words
(defn SHA1-extend-words [#^bytes buf]
	(loop [words (into [] (map #(bytes-to-int (barray %)) (partition 4 buf))) i (count words)]
		(if (= i 80) words
			(recur (conj words
						(-> (nth words (- i 3))
						(bit-xor (nth words (- i 8)))
						(bit-xor (nth words (- i 14)))
						(bit-xor (nth words (- i 16)))
						(left-rotate 1)))
				   (inc i)))))

;Require math functions to overflow like in Java and not do automatic promotion
(set! *unchecked-math* true)

;Use this function to hash a 512-bit chunk as SHA-1
(defn SHA1-hash-block
([#^bytes buf]
	(SHA1-hash-block buf [h0 h1 h2 h3 h4]))
([#^bytes buf #^Integer h-vals]
	(let [words (SHA1-extend-words buf)]
		(loop [i 0 abcde h-vals]
			(let [[a b c d e] abcde
				  [f k] 	  (cond (<= i 19) [(bit-xor d (bit-and b (bit-xor c d))) 0x5A827999]
							  		(<= i 39) [(bit-xor b c d) 0x6ED9EBA1]
							  		(<= i 59) [(bit-or (bit-and b c) (bit-and d (bit-or b c))) 0x8F1BBCDC]
							  		:else     [(bit-xor b c d) 0xCA62C1D6])
				  result [(+ (left-rotate a 5) f e k (nth words i)) a (left-rotate b 30) c d]]
				(if (= i 79) (map #(int (+ %1 %2)) result h-vals)
						     (recur (inc i) result)))))))

;Call this on a string or byte array to get the SHA1 hash
;Two parameter function is used for length extension attacks
(defn SHA1-hash
([buf] (SHA1-hash (partition 64 (SHA1-preprocess buf)) [h0 h1 h2 h3 h4]))
([chunks hvals]
	(let [digest (loop [chunks chunks digest-vals hvals]
					(if (empty? chunks) digest-vals
						(recur (rest chunks) (SHA1-hash-block (first chunks) digest-vals))))]
		(->> (map int-to-bytes digest)
			 (concat-bytes-to-array)
			 (DatatypeConverter/printHexBinary)
		 	 (.toLowerCase)))))

;Java digest SHA-1 to test against
(defn get-hash [type data]
(.digest (java.security.MessageDigest/getInstance type) (.getBytes data) ))

(defn sha1-hash [data]
 (get-hash "sha1" data))

(defn get-hash-str [data-bytes]
  (apply str
	(map #(.substring (Integer/toString (+ (bit-and % 0xff) 0x100) 16) 1) data-bytes)))

;Here is the mac function
(defn create-mac
([hash-fn s key]
	(hash-fn (concat-bytes-to-array [(sanitize-str-bytes key) (sanitize-str-bytes s)]))))

(defn test-challenge28 []
	(println "Testing challenge 28:")
	(println "Have we implemented SHA1 in clojure correctly?")
	(println (letfn [(SHA1-test [s] (= (SHA1-hash s) (get-hash-str (sha1-hash s))))]
					(every? true? [(SHA1-test "")
				   				   (SHA1-test "Hello world")
								   (SHA1-test "The quick brown fox jumped over the lazy dog")
				   				   (SHA1-test "ASDIOJASOFJ DSPOCASMPIUFYVNASIDOi IUADSCIOPUDCNASUIN CASDASHUINMCUDHASNUOIDCNASHUOIDCHA")]))))

;;;;;;;;;;;;;;;;;; CHALLENGE 29 ;;;;;;;;;;;;;;;;;;

(def c29-secret-key "So fresh so clean")
(def c29-str "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
(defn c29-SHA1-mac [s] (create-mac SHA1-hash s c29-secret-key))
(def c29-mac (c29-SHA1-mac c29-str))

(defn SHA1-hex-to-digest [^String hash]
	(->> (DatatypeConverter/parseHexBinary hash)
		 (partition 4)
		 (map #(bytes-to-int (barray %)))))

;Generate chunks to apply for length extension attack, requires the previous number of blocks
(defn SHA1-attack-chunk [^String message-to-inject ^Long prev-blocks]
	(let [chunk          (SHA1-preprocess message-to-inject)
	      message-length (bytes-to-long (barray (take-last 8 chunk)))]
		(partition 64 (concat (drop-last 8 chunk) (long-to-bytes (+ message-length (* 512 prev-blocks)))))))

;Do an SHA1-length extension attack
;@message - the original message
;@attack-str - the string we want to inject
;@mac-fn - the mac function for which we do not know the secret key
;Returns the hash value and what was hashed with the mac function as a vector
(defn SHA1-length-extension-attack [^String message ^String attack-str mac-fn]
	(let [mac            (mac-fn message)
		  mac-digest     (SHA1-hex-to-digest mac)
		  message-length (count message)
		  message-bytes  (.getBytes message)
		  attack-bytes   (.getBytes attack-str)]
		(loop [key-length-guess 0]
			(let [prev-block-count (inc (quot (+ message-length key-length-guess) 64))
				  attempt          (SHA1-hash (SHA1-attack-chunk attack-str prev-block-count) mac-digest)
				  injected-message (concat-bytes-to-array [message-bytes (hash-padding (+ message-length key-length-guess) ByteOrder/BIG_ENDIAN) attack-bytes])]
				(if (= (mac-fn injected-message) attempt)
					[attempt injected-message]
					(recur (inc key-length-guess)))))))

(defn test-challenge29 []
	(println "Testing challenge 29:")
	(println "Can we do a SHA1 length extension attack?")
	(let [attack (SHA1-length-extension-attack c29-str ";admin=true;" c29-SHA1-mac)]
		(println "Found hash:" (first attack) "\nFor string: " (String. (second attack) "UTF-8") "\nWhich has mac:" (c29-SHA1-mac (second attack)))))

;;;;;;;;;;;;;;;;;; CHALLENGE 30 ;;;;;;;;;;;;;;;;;;

(def A 0x67452301)
(def B 0xefcdab89)
(def C 0x98badcfe)
(def D 0x10325476)

(defn bit-flip-all [x] (bit-and (bit-xor x 0xFFFFFFFF) 0xFFFFFFFF))

;Pass in a block of 64 bytes
(defn MD4-hash-block
([#^bytes buf]
	(MD4-hash-block buf [A B C D]))
([#^bytes buf #^Integer digest-vals]
	(letfn [(f [x y z] (bit-or (bit-and x y) (bit-and (bit-flip-all x) z)))
		      (g [x y z] (bit-or (bit-and x y) (bit-and x z) (bit-and y z)))
		      (h [x y z] (bit-xor x y z))
		      (f1 [a b c d k s X] (left-rotate (+ a (f b c d) (nth X k)) s))
		      (f2 [a b c d k s X] (left-rotate (+ a (g b c d) (nth X k) 0x5a827999) s))
			    (f3 [a b c d k s X] (left-rotate (+ a (h b c d) (nth X k) 0x6ed9eba1) s))]
		(let [X         (into [] (map #(bytes-to-int (barray %) ByteOrder/LITTLE_ENDIAN) (partition 4 buf)))
          [a b c d] digest-vals
          A         (atom a)
          B         (atom b)
          C         (atom c)
          D         (atom d)]
         (reset! A (f1 @A @B @C @D 0 3 X))
         (reset! D (f1 @D @A @B @C 1 7 X))
         (reset! C (f1 @C @D @A @B 2 11 X))
         (reset! B (f1 @B @C @D @A 3 19 X))
         (reset! A (f1 @A @B @C @D 4 3 X))
         (reset! D (f1 @D @A @B @C 5 7 X))
         (reset! C (f1 @C @D @A @B 6 11 X))
         (reset! B (f1 @B @C @D @A 7 19 X))
         (reset! A (f1 @A @B @C @D 8 3 X))
         (reset! D (f1 @D @A @B @C 9 7 X))
         (reset! C (f1 @C @D @A @B 10 11 X))
         (reset! B (f1 @B @C @D @A 11 19 X))
         (reset! A (f1 @A @B @C @D 12 3 X))
         (reset! D (f1 @D @A @B @C 13 7 X))
         (reset! C (f1 @C @D @A @B 14 11 X))
         (reset! B (f1 @B @C @D @A 15 19 X))

         (reset! A (f2 @A @B @C @D 0 3 X))
         (reset! D (f2 @D @A @B @C 4 5 X))
         (reset! C (f2 @C @D @A @B 8 9 X))
         (reset! B (f2 @B @C @D @A 12 13 X))
         (reset! A (f2 @A @B @C @D 1 3 X))
         (reset! D (f2 @D @A @B @C 5 5 X))
         (reset! C (f2 @C @D @A @B 9 9 X))
         (reset! B (f2 @B @C @D @A 13 13 X))
         (reset! A (f2 @A @B @C @D 2 3 X))
         (reset! D (f2 @D @A @B @C 6 5 X))
         (reset! C (f2 @C @D @A @B 10 9 X))
         (reset! B (f2 @B @C @D @A 14 13 X))
         (reset! A (f2 @A @B @C @D 3 3 X))
         (reset! D (f2 @D @A @B @C 7 5 X))
         (reset! C (f2 @C @D @A @B 11 9 X))
         (reset! B (f2 @B @C @D @A 15 13 X))

         (reset! A (f3 @A @B @C @D 0 3 X))
         (reset! D (f3 @D @A @B @C 8 9 X))
         (reset! C (f3 @C @D @A @B 4 11 X))
         (reset! B (f3 @B @C @D @A 12 15 X))
         (reset! A (f3 @A @B @C @D 2 3 X))
         (reset! D (f3 @D @A @B @C 10 9 X))
         (reset! C (f3 @C @D @A @B 6 11 X))
         (reset! B (f3 @B @C @D @A 14 15 X))
         (reset! A (f3 @A @B @C @D 1 3 X))
         (reset! D (f3 @D @A @B @C 9 9 X))
         (reset! C (f3 @C @D @A @B 5 11 X))
         (reset! B (f3 @B @C @D @A 13 15 X))
         (reset! A (f3 @A @B @C @D 3 3 X))
         (reset! D (f3 @D @A @B @C 11 9 X))
         (reset! C (f3 @C @D @A @B 7 11 X))
         (reset! B (f3 @B @C @D @A 15 15 X))

         (map #(int (+ %1 %2)) [a b c d] [@A @B @C @D])))))

(defn MD4-preprocess [buf]
	(let [buf-bytes (sanitize-str-bytes buf)]
	(concat buf-bytes (hash-padding (count buf-bytes) ByteOrder/LITTLE_ENDIAN))))

;Actual hashing function
(defn MD4-hash
([buf] (MD4-hash (partition 64 (MD4-preprocess buf)) [A B C D]))
([chunks hvals]
	(let [digest (loop [chunks chunks digest-vals hvals]
					(if (empty? chunks) digest-vals
						(recur (rest chunks) (MD4-hash-block (first chunks) digest-vals))))]
		(->> (map #(int-to-bytes % ByteOrder/LITTLE_ENDIAN) digest)
			 (concat-bytes-to-array)
       (DatatypeConverter/printHexBinary)
		 	 (.toLowerCase)))))

;Mac function and attack here
(def c30-secret-key "Hash attack")
(def c30-str "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
(defn c30-MD4-mac [s] (create-mac MD4-hash s c30-secret-key))
(def c30-mac (c30-MD4-mac c30-str))

(defn MD4-hex-to-digest [^String hash]
	(->> (DatatypeConverter/parseHexBinary hash)
		 (partition 4)
		 (map #(bytes-to-int (barray %) ByteOrder/LITTLE_ENDIAN))))

;Generate chunks to apply for length extension attack, requires the previous number of blocks
(defn MD4-attack-chunk [^String message-to-inject ^Long prev-blocks]
	(let [chunk          (MD4-preprocess message-to-inject)
	      message-length (bytes-to-long (barray (take-last 8 chunk)) ByteOrder/LITTLE_ENDIAN)]
		(partition 64 (concat (drop-last 8 chunk) (long-to-bytes (+ message-length (* 512 prev-blocks)) ByteOrder/LITTLE_ENDIAN)))))

;Do an SHA1-length extension attack
;@message - the original message
;@attack-str - the string we want to inject
;@mac-fn - the mac function for which we do not know the secret key
;Returns the hash value and what was hashed with the mac function as a vector
(defn MD4-length-extension-attack [^String message ^String attack-str mac-fn]
	(let [mac            (mac-fn message)
		    mac-digest     (MD4-hex-to-digest mac)
		    message-length (count message)
		    message-bytes  (.getBytes message)
		    attack-bytes   (.getBytes attack-str)]
		(loop [key-length-guess 0]
			(let [prev-block-count (inc (quot (+ message-length key-length-guess) 64))
				    attempt          (MD4-hash (MD4-attack-chunk attack-str prev-block-count) mac-digest)
				    injected-message (concat-bytes-to-array [message-bytes (hash-padding (+ message-length key-length-guess) ByteOrder/LITTLE_ENDIAN) attack-bytes])]
				(if (= (mac-fn injected-message) attempt)
					[attempt injected-message]
					(recur (inc key-length-guess)))))))

(defn test-challenge30 []
	(println "Testing challenge 30:")
	(println "Can we do a MD4 length extension attack?")
	(let [attack (MD4-length-extension-attack c30-str ";admin=true;" c30-MD4-mac)]
		(println "Found hash:" (first attack) "\nFor string: " (String. (second attack) "UTF-8") "\nWhich has mac:" (c30-MD4-mac (second attack)))))

;;;;;;;;;;;;;;;;;; CHALLENGE 31 ;;;;;;;;;;;;;;;;;;

(def HMAC-BLOCKSIZE 64)
;Same key as server has
(def c31-key (repeat 64 0x11))

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

(require '[clj-http.client :as client])

(def HEX-CHARS (apply vector "0123456789abcdef"))
(def BASE-HASH-BYTES (barray (repeat 20 -128)))
(def SERVER-BASE-PATH "http://localhost:3000/test/")

(defn c31-server-request [file signature]
  (str SERVER-BASE-PATH file "/" signature))

(defn inc-byte [buf pos]
  (let [c (nth buf pos)]
   (barray (assoc (vec buf) pos (inc c)))))

;Average the response time to the url for the number of attempts
;Does an extra 3 requests and drops the top 3 to remove jitter
;Only drop top requests because unlikely to get unusually low response time...
;But many reasons can large delays
(defn average-requests [request-url attempts]
  (->> (for [x (range (+ attempts 3))]
         (let [start (System/currentTimeMillis)]
           (try (do (client/get request-url) (- (System/currentTimeMillis) start))
                (catch Exception e (- (System/currentTimeMillis) start)))))
       (sort)
       (drop-last 3)
       (apply +)
       ((fn [x] (/ x attempts)))
       (int)))

(defn average-base-connection [file]
  (average-requests (c31-server-request file (DatatypeConverter/printHexBinary BASE-HASH-BYTES)) 50))

;Factory method to break an HMAC.
;Takes a url, the number of requests to average, and the char-delay to check for a successful char
(defn break-HMAC-factory [url-fn request-num char-delay]
  (fn [file]
  (loop [break-attempt BASE-HASH-BYTES
         attempt-time  (average-base-connection file)
         byte-pos      0]
  (let [hex-vals        (DatatypeConverter/printHexBinary break-attempt)
        request-url     (url-fn file hex-vals)
        do-recur        (atom false)
        after-time      (atom 0)
        before-req-time (System/currentTimeMillis)]
    (if (>= byte-pos 20) (do (println "Found: " (clojure.string/lower-case hex-vals))
                           (clojure.string/lower-case hex-vals))
        (let [time-diff (average-requests request-url request-num)]
          (if (> time-diff (+ attempt-time char-delay))
           (do (println "Currently broken:" hex-vals)
             (recur break-attempt time-diff (inc byte-pos)))
           (recur (inc-byte break-attempt byte-pos) attempt-time byte-pos))))))))

(defn c31-break-HMAC [file]
  ((break-HMAC-factory c31-server-request 2 40) file))

(defn test-challenge31 []
  (println "Do we have a proper SHA1-HMAC?")
  (println (every? true? [(= (HMAC-SHA1 "" "") "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
                          (= (HMAC-SHA1 "key" "The quick brown fox jumps over the lazy dog") "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")]))
  (println "Can we break an HMAC with timing delay of 50msec? (Make sure server is running)")
  (println (= (:body (client/get "http://localhost:3000/verify/file")) (c31-break-HMAC "file"))))

;;;;;;;;;;;;;;;;;; CHALLENGE 32 ;;;;;;;;;;;;;;;;;;

(def c32-key c31-key)

(defn c32-server-request [file signature]
  (str "http://localhost:3000/test2/" file "/" signature))

(defn c32-break-HMAC [file]
  ((break-HMAC-factory c32-server-request 15 3) file))

(defn test-challenge32 []
    (println "Make sure server is running. May take a long time.")
  (println "Can we break an HMAC with timing delay of 5msec?")
  (println (= (:body (client/get "http://localhost:3000/verify/file")) (c32-break-HMAC "file"))))

;;;;;;;;;;;;;;;;;; CHALLENGE 32 ;;;;;;;;;;;;;;;;;;

(defn test-all []
  (test-challenge25)
  (test-challenge26)
  (test-challenge27)
  (test-challenge28)
  (test-challenge29)
  (test-challenge30)
  (test-challenge31)
  (test-challenge32))
