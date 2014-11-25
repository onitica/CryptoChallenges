(ns native-impl.hash
  (:import javax.xml.bind.DatatypeConverter
           (java.nio ByteBuffer ByteOrder)))

;;;;;;;;;;;;;;;;;;; UTILITY FUNCTIONS ;;;;;;;;;;;;;;;;;;;

;Convenience function for casting colls to byte arrays
(defn barray [coll]
	(byte-array (map byte coll)))

(defn bytes-to-string [coll]
	(String. (barray coll) "UTF-8"))

(defn concat-bytes-to-array [b]
	(barray (apply concat b)))

;If passed a byte array or string will return a byte array, otherwise will throw a helpful exception
(defn sanitize-str-bytes [s]
	(let [ctype (class s)]
		(cond (= String ctype) (.getBytes s "UTF-8")
	          (= (Class/forName "[B") ctype) s
		      (coll? s) (barray s)
	          :else (throw (Exception. "Must pass in either a string, byte array, or collection to sanitize-str-bytes fn!")))))

;Unsigned right shift operator
(defn >>> [^Integer v ^Short bits]
  (bit-shift-right (bit-and 0xFFFFFFFF v) bits))

;Assumes 32-bit word size, super inefficient but clojure doesn't have good syntax for this
(defn left-rotate [^Integer w ^Integer shift]
  (bit-and (bit-xor (bit-shift-left w shift) (>>> w (- 32 shift))) 0xFFFFFFFF))

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

;;;;;;;;;;;;;;;;;;; SHA1 ALGORITHM ;;;;;;;;;;;;;;;;;;;

;Constants defined for SHA1-hash
(def h0 0x67452301)
(def h1 0xEFCDAB89)
(def h2 0x98BADCFE)
(def h3 0x10325476)
(def h4 0xC3D2E1F0)

;Inefficient and barely tested implementation of SHA1 in Clojure, made by yours truly

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
				   (inc i)))
	))

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
						     (recur (inc i) result))))
	)))

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

;;;;;;;;;;;;;;;;;;; MD4 ALGORITHM ;;;;;;;;;;;;;;;;;;;

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

;;;;;;;;;;;;;;;;;;; TESTING ;;;;;;;;;;;;;;;;;;;

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

(defn test-SHA1 []
	(println "Testing SHA1 implementation:")
	(println "Have we implemented SHA1 in clojure correctly?")
	(println (letfn [(SHA1-test [s] (= (SHA1-hash s) (get-hash-str (sha1-hash s))))]
					(every? true? [(SHA1-test "")
                         (SHA1-test "a")
                         (SHA1-test "so fresh so clean")
				   				       (SHA1-test "Hello world")
								         (SHA1-test "The quick brown fox jumped over the lazy dog")
				   				       (SHA1-test "ASDIOJASOFJ DSPOCASMPIUFYVNASIDOi IUADSCIOPUDCNASUIN CASDASHUINMCUDHASNUOIDCNASHUOIDCHA")]))))

(defn test-MD4 []
	(println "Testing MD4 implementation:")
	(println "Have we implemented MD4 in clojure correctly?")
  (println (letfn [(MD4-test [s v] (= (MD4-hash s) v))]
					(every? true? [(MD4-test "" "31d6cfe0d16ae931b73c59d7e0c089c0")
                         (MD4-test "a" "bde52cb31de33e46245e05fbdbd6fb24")
                         (MD4-test "abc" "a448017aaf21d8525fc10ae87aa6729d")
                         (MD4-test "message digest" "d9130a8164549fe818874806e1c7014b")
                         (MD4-test "abcdefghijklmnopqrstuvwxyz" "d79e1c308aa5bbcdeea8ed63df412da9")
                         (MD4-test "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "043f8582f241db351ce627e153e7f0e4")
                         (MD4-test "12345678901234567890123456789012345678901234567890123456789012345678901234567890" "e33b4ddc9c38f2199c3e7b164fcc0536")]))))

