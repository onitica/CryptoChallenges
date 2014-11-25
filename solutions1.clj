;;;;; UTILITY FUNCTIONS AND DEFINITIONS

;Define values to encode with
(def base64-chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
(def hex-chars "0123456789abcdef")

;Converts a radix to base 10
;coll - A collection of the digits to convert
;char-table - The mapping of chars to the base10 value, i.e. the index in string is base10 value
(defn radix-to-base10 [coll char-table]
	(let [radix (count char-table)]
	(loop [coll (reverse coll) pow 1 res 0]
		(cond (seq coll) (recur (rest coll)
								(* radix pow)
								(+ res (* (.indexOf char-table (str (first coll))) pow)))
			  :else res))))

;Splits a number n into smaller chunks and then converts to string of new characters from table
;Size is the total number of smaller chunks in the value passed in
;Chars is the character map used to convert the base values to characters (must be a power of 2)
;Returns a function that can be used - is a closure over temp variables
(defn bit-split-convert-creator [size chars]
	(let [shift (int (/ (Math/log (count chars)) (Math/log 2)))
		  mask (- (int (Math/pow 2 shift)) 1)
		  shift-array (map #(* shift %) (reverse (range size)))]
	(fn [n]		
		(apply str 
		(for [x shift-array]
			(->> x
				 (bit-shift-right n)
				 (bit-and mask)
				 (nth chars)))))))

;;;;;;;;;;;;;;;;;; CHALLENGE 1 ;;;;;;;;;;;;;;;;;;

;Horribly inefficient solution and probably over abstracted
;Testing out a bunch of clojure features when creating this

;Define challenge strings
(def test-sh "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
(def test-sb "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

;Define block ratios here
;A value of [4 6] means there every 4 blocks of base64 is equivalent to 6 blacks of hex
;An easy way to account for padding would be to make this [2 3] and just strip = signs
(def ratio [4 6]) 
(def base64-ratio (ratio 0))
(def hex-ratio (ratio 1))

(def convert-hex-to-base64 
	(bit-split-convert-creator base64-ratio base64-chars))

;Convert a hex string to base 64
(defn hex-str-to-base64 [s]
	(->> s
		(partition hex-ratio)
		(map #(radix-to-base10 % hex-chars))	
		(map convert-hex-to-base64)
		(apply str)))

(def convert-base64-to-hex 
	(bit-split-convert-creator hex-ratio hex-chars))

;Convert a base64 str to hex
(defn base64-str-to-hex [s]
	(->> s
		(partition base64-ratio)
		(map #(radix-to-base10 % base64-chars))
		(map convert-base64-to-hex)
		(apply str)))

;Tests 
(defn test-challenge1 []
	(println "Testing challenge 1")
	(println "Convert hex string to base64 working?")
	(println (= test-sb (hex-str-to-base64 test-sh)))
	(println "Convert base64 string to hex working?")
	(println (= test-sh (base64-str-to-hex test-sb))))

;;;;;;;;;;;;;;;;;; CHALLENGE 2 ;;;;;;;;;;;;;;;;;;

;Define challenge strings
(def hex1 "1c0111001f010100061a024b53535009181c")
(def hex2 "686974207468652062756c6c277320657965")
(def sum-hex "746865206b696420646f6e277420706c6179")

(defn xor-hex-strs [h1 h2]
	(let [hex1 (->> h1 (partition 1) (map #(radix-to-base10 % hex-chars)))
		  hex2 (->> h2 (partition 1) (map #(radix-to-base10 % hex-chars)))]
	(apply str (map #(nth hex-chars %) (map bit-xor hex1 hex2)))))

(defn test-challenge2 []
	(println "Testing challenge 2")
	(println "XOR hex strings working?")
	(println (= sum-hex (xor-hex-strs hex1 hex2))))

;;;;;;;;;;;;;;;;;; CHALLENGE 3 ;;;;;;;;;;;;;;;;;;

;Demo text to build frequency map from
(def demo-text (slurp "text/demotext.txt"))
;Encoded challenge string
(def encoded-string "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

;Build a frequency map from a string
(defn build-frequency-map [s]
	(let [total-chars (count s)
		  freqs (frequencies s)]
			  (zipmap (keys freqs) (map #(/ % total-chars) (vals freqs)))))

;Default english frequency map
(def english-freq-map (build-frequency-map demo-text))

;Score a string (s) with respect to a frequency map
;Get sum of absolute differences of frequencies between intersecting chars in the two frequency maps to get a base score
;Automatically discounts strings with characters not in the original frequency map and returns 100 (could use a penalty instead if we wanted to)
(defn score-string [s freq-map]
	(if (every? #(freq-map %) s)
	(let [s-freq-map (build-frequency-map s)
	      diff (reduce +
					(->> (merge-with list freq-map s-freq-map)
					(vals)
					(filter list?)
					(map #(apply - %))
					(map #(if (< 0 %) % (- %)))))]
		 diff) 100))

;Convert a string of hex characters to utf8
(defn unhexify [hex]
  (apply str
    (map 
      (fn [[x y]] (char (Integer/parseInt (str x y) 16))) 
      (partition 2 hex))))

;Making assumption that string is valid ascii - so it will always have even length
;Inner loop uses 2 hex-value counters to loop through possible hex-encoded strings
;Returns a vector with the result string and its decoding score and the encryption character if successful
(defn single-xor-decrypt-hex 
	([s] (single-xor-decrypt-hex s english-freq-map))
	([s freq-map]
	(let [length (count s)
	      s-radix-10 (->> s (partition 1) (map #(radix-to-base10 % hex-chars)))]
		(loop [hex1 0 hex2 0 best-score 1 result "" xor-char -1]
			(if (< hex2 16) 
					(let [new-hex (reduce concat (repeat (/ length 2) [hex2 hex1]))
						  decode-attempt (unhexify (apply str (map #(nth hex-chars %) (map bit-xor s-radix-10 new-hex))))
						  score (score-string decode-attempt freq-map)
						  new-hex1-val (if (= hex1 15) 0 (+ 1 hex1))
						  new-hex2-val (if (= hex1 15) (+ 1 hex2) hex2)]	
						  (if (< score best-score) 
							  (recur new-hex1-val new-hex2-val score decode-attempt [hex1 hex2])
							  (recur new-hex1-val new-hex2-val best-score result xor-char)))
				[result best-score (if (vector? xor-char) 
									   (char (+ (bit-shift-left (second xor-char) 4) (first xor-char)))
									   xor-char)])))))

(defn test-challenge3 []
	(println "Testing challenge 3")
	(println "Can we can decode the xor-encoded string?")
	(println (= (first (single-xor-decrypt-hex encoded-string)) "Cooking MC's like a pound of bacon")))

;;;;;;;;;;;;;;;;;; CHALLENGE 4 ;;;;;;;;;;;;;;;;;;

;Kind of slow because decryption is so unoptimized - pmap helps though since decoding them is embarrassingly parallel

(def xor-encoded-gistfile-strings (clojure.string/split-lines (slurp "text/challenge4.txt")))

(defn find-decoded-string [string-vec]
	(first	
	(reduce #(if (< (second %1) (second %2)) %1 %2) 
			(pmap single-xor-decrypt-hex string-vec))))

(defn test-challenge4 []
	(println "Testing challenge 4")
	(println "Can we decrypt the properly encoded xor-string?")
	(println (= (find-decoded-string xor-encoded-gistfile-strings) "Now that the party is jumping\n")))

;;;;;;;;;;;;;;;;;; CHALLENGE 5 ;;;;;;;;;;;;;;;;;;

;Challenge strings
(def text-to-encrypt "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal")
(def encryption-key "ICE")
(def encrypted-text "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

;Convert a string to a hex string
(defn hexify [s]
  (apply str
    (map #(format "%02x" (int %)) s)))

;Xor encrypts hex string s by the key
;Returns the encrypted string in hex-encoding
(defn xor-encrypt-hex-str [s key]
	(let [hex-key (hexify key)
		  hex-strings (partition-all (count hex-key) s)]
		(apply str (map #(xor-hex-strs % hex-key) hex-strings))))

;Wrapper for passing in regular string instead of hex string
(defn xor-encrypt-string [s key]
	(xor-encrypt-hex-str (hexify s) key))

(defn test-challenge5 []
	(println "Testing challenge 5")
	(println "Encrypting test string with ICE equals correct hex value?")
	(println (= (xor-encrypt-string text-to-encrypt encryption-key) encrypted-text)))

;;;;;;;;;;;;;;;;;; CHALLENGE 6 ;;;;;;;;;;;;;;;;;;

;Challenge strings
;Read string from file, strip newline characters and then convert to hex from base64
(def challenge6-encrypted-hex (base64-str-to-hex (clojure.string/replace (slurp "text/challenge6.txt") #"\n" "")))

;Calculate the hamming-weight of an integer
(defn hamming-weight [x]
	(loop [x x res 0]
		(if (= x 0) res
			(recur (bit-shift-right x 1) (+ res (bit-and x 1))))))

;Calculate the hamming-distance between two strings
(defn hamming-distance 
	([s1 s2]
		(hamming-distance s1 s2 0))
	([s1 s2 result]
		(cond (every? true? (map empty? (list s1 s2)))
			  result
			  :else (recur (rest s1) (rest s2) (->> (bit-xor (int (first s1)) (int (first s2)))
													(hamming-weight)
													(+ result))))))

;Helper functions for finding the hamming distance of blocks
(defn subs-hamming [s begin size]
	(let [end (+ begin size)]
		(/ (hamming-distance (subs s begin end) (subs s end (+ end size))) size)))

;Find average of hamming distance of xoring first four blocks as described in the challenge
(defn hamming-first-four-block-avg [s size]
	(/ (reduce + (map #(subs-hamming s (* size %) size) (range 4))) 4))	

;Find the keysize of the encrypted XOR string (passed in hex encoded)
;Returns a list of the first 5 possible keysizes sorted by score order
(defn possible-KEYSIZES
	([s]
		(possible-KEYSIZES s 38))
	([hex-s r]
		(let [s (unhexify hex-s)
			  sizes-to-check (map #(+ 2 %) (range r))]
		(->> sizes-to-check
			 (map #(vector (hamming-first-four-block-avg s %) %))
			 (flatten)
			 (apply sorted-map)
			 (vals)
			 (take 5)))))

;Assume s passed in is a hex encoded string
;We are mapping hex chars to extended ascii chars - So we need to map elements as 2 hex chars first 
;Tranposes the matrix created by partitioning the original characters a value of size (i.e. a size of 6 means turning a Nx6 matrix to 6xN, where N is the length of s divided by size)
(defn transpose-hex-str [s size]
	(->> s
		 (partition 2)
		 (map #(apply str %))
		 (partition size)
		 (apply map str)))

;Use this to find an XOR string for a bunch of encrypted XOR text
;Assumes a hex encoded string is passed in
;Returns nil if unable tofind the key
(defn find-key 
	([s]
		(find-key s 38))
	([s size]
		(let [keysizes (possible-KEYSIZES s size)] 
			(loop [keysizes keysizes]
				(when (seq keysizes)
					  (let [keysize (first keysizes)
							single-keys (pmap #(nth (single-xor-decrypt-hex %) 2) (transpose-hex-str s keysize))]
							(cond (some #{-1} single-keys)
								  (recur (rest keysizes))
								  :else (apply str single-keys))))))))

;Use this to actually decrypt the text if you want
;Returns nil if unable to decrypt
(defn decrypt-xor-encoded-hex 
	([s]
		(when-let [key (find-key s)]
			(decrypt-xor-encoded-hex s key)))
	([s key]
		(unhexify (xor-encrypt-hex-str s key))))

(defn test-challenge6 []
	(println "Testing challenge 6")
	(println "Do we have a proper hamming distance function?")
	(println (= (hamming-distance "this is a test" "wokka wokka!!!") 37))
	(println "Can we find the key for this challenge?")
	(println (= "Terminator X: Bring the noise" (find-key challenge6-encrypted-hex))))

;;;;;;;;;;;;;;;;;; CHALLENGE 8 ;;;;;;;;;;;;;;;;;;

;Idea to detect if a string is encrypted by a deterministic key 
;Detect duplicate 16-byte blocks to figure out if it is ECB encrypted

;Load in challenge string and strip newlines
(def challenge8-encrypted-hex (clojure.string/split (slurp "text/challenge8.txt") #"\n"))
(def challenge8-solution "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")

;32 hex chars should be equivalent to 16 bytes of char data
(defn score-is-ecb-encrypted-hex [s]
		(let [repeats (->> (partition 32 s)
			 			(group-by identity)
			 			(vals)
						(map count)
						(filter (partial < 2)))
			  score (if (empty? repeats) 0 (reduce + repeats))]
			[score s]))

(defn determine-ecb-encrypted-hex-string [encrypted-strs]
	(->> encrypted-strs
		(map #(score-is-ecb-encrypted-hex %))
		(flatten)
		(apply sorted-map-by >)
		(first)
		(second)))

(defn test-challenge8 []
	(println "Testing challenge 8")
	(println "Can we find the ecb encrypted string?")
	(println (= (determine-ecb-encrypted-hex-string challenge8-encrypted-hex) challenge8-solution)))

;;;;;;;;;;;;;;;;;; TEST ALL SOLUTIONS IN FILE ;;;;;;;;;;;;;;;;;;

;Call this to test challenges 1-6,8

(defn test-all []
	(test-challenge1)
	(test-challenge2)
	(test-challenge3)
	(test-challenge4)
	(test-challenge5)
	(test-challenge6)
	(test-challenge8))

