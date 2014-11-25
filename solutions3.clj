;;;;;;;;;;;;;;;;;; UTILITY FUNCTIONS AND DEFINITIONS ;;;;;;;;;;;;;;;;;;

;Use this for converting Java data to bytes
(import javax.xml.bind.DatatypeConverter)

(defn base64-to-bytes [^String s]
	(DatatypeConverter/parseBase64Binary s))

;Convenience function for casting colls to byte arrays
(defn barray [coll]
	(byte-array (map byte coll)))

(defn bytes-to-string [coll]
	(String. (barray coll) "UTF-8"))

(defn concat-bytes-to-array [b]
	(barray (apply concat b)))

(def all-byte-values (map #(- % 128) (range 256)))

;If passed a byte array or string will return a byte array, otherwise will throw a helpful exception
(defn sanitize-str-bytes [s]
	(let [ctype (class s)]
		(cond (= String ctype) (.getBytes s "UTF-8")
			  (= (Class/forName "[B") ctype) s
			  :else (throw (Exception. "Must pass in either a string or byte array to sanitize-str-bytes fn!")))))

(defn read-lines [f] (clojure.string/split (slurp f) #"\n"))

(defn indices [pred coll]
   (keep-indexed #(when (pred %2) %1) coll))

;;;;;;;;;;;;;;;;;; OLD FUNCTIONS NEEDED ;;;;;;;;;;;;;;;;;;

;PKCS7-Padding functions
;s is the string/bytes to pad, n is the length of the block size
;Can take either a string or array of bytes
(defn Pad-PKCS7 [s ^Integer n]
	(let [^Integer diff (- n (rem (count s) n))]
		(cond (< diff 0) nil
			  (= diff 0) (concat s (repeat n (char n)))
			  :else (concat s (repeat diff (char diff))))))	

(defn Pad-PKCS7-String [^String s ^Integer n]
	(apply str (Pad-PKCS7 s n)))

(defn ^bytes Pad-PKCS7-Bytes [s ^Integer n]
	(barray (Pad-PKCS7 s n)))

;Must take in either string or bytes -> returns a collection if valid or else throws an exception
;Methodology -> Reverse block, take while the bytes are equal, check if all the bytes are equal to the length of the equal bytes
(defmulti valid-PKCS7-Padding? class)
(defmethod valid-PKCS7-Padding? String [s] (valid-PKCS7-Padding? (.getBytes s)))
(defmethod valid-PKCS7-Padding? (Class/forName "[B") [block] 
	(let [end-repeats (take-while #(= (last block) %) (reverse block))
		  pad         (count end-repeats)]
		(if (apply = pad end-repeats)
			(drop-last pad block)
			(throw (Exception. "Bad Padding Exception")))))

;Encryption functions
(import (java.security Key)
      (javax.crypto Cipher)
      (javax.crypto.spec SecretKeySpec))

;ECB encryption functions
;Assumes passed UTF-8 Strings
(defmulti ^Key secret class)
(defmethod ^Key secret String [s] (secret (.getBytes s)))
(defmethod ^Key secret (Class/forName "[B") [b] (SecretKeySpec. b "AES"))

;Can pass in either strings or bytes
(defn ^bytes encrypt-ECB [s key]
  (let [cipher (doto (Cipher/getInstance "AES/ECB/NoPadding")
                     (.init Cipher/ENCRYPT_MODE (secret key)))]
	(if (isa? String (class s))
    	(.doFinal cipher (.getBytes s "UTF-8"))
		(.doFinal cipher s))))

;Buffer must be a byte array, but the key can be passed in as either bytes or a string
(defn decrypt-ECB [^bytes buf key]
  (let [cipher (doto (Cipher/getInstance "AES/ECB/NoPadding")
               (.init Cipher/DECRYPT_MODE (secret key)))]
    (.doFinal cipher buf)))

(defn ^String decrypt-ECB-String [^bytes buf key]
	(String. (decrypt-ECB buf key) "UTF-8"))

;Use this to bit-xor two equal size collections of byte blocks
;Returns an array of byte blocks
(defn ^bytes bit-xor-blocks [^bytes b1 ^bytes b2]
	(barray (map bit-xor b1 b2)))

(def CBC-KEYSIZE 16)
(def EMPTY-IV (barray (repeat 16 0)))

(defn first-block [b] (take CBC-KEYSIZE b))
(defn rest-buf [b] (drop CBC-KEYSIZE b))
(defn last-block [b] (take-last CBC-KEYSIZE b))
(defn drop-last-block [b] (drop-last CBC-KEYSIZE b))

;Key can be passed in as either a byte array or a string
(defn ^bytes encrypt-CBC [^bytes buf key ^bytes IV]
	(loop [start (first-block buf) rem (rest-buf buf) blocks [IV]]
		(let [b (conj blocks (encrypt-ECB (bit-xor-blocks start (last blocks)) key))]
			(cond (empty? rem) (concat-bytes-to-array (drop 1 b))
				  :else (recur (first-block rem) (rest-buf rem) b)))))

(defn decrypt-CBC [^bytes buf key ^bytes IV]
	(loop [start (first-block buf) rem (rest-buf buf) blocks [] last-block IV]
		(let [b (conj blocks (bit-xor-blocks (decrypt-ECB (barray start) key) last-block))]
			(cond (empty? rem) (concat-bytes-to-array b)
				  :else (recur (first-block rem) (rest-buf rem) b start))) ))

;Wrapper around decrypt CBC function to retun a string
(defn ^String decrypt-CBC-String [^bytes buf key ^bytes IV]
	(String. (decrypt-CBC buf key IV) "UTF-8"))

;Generate random byte
;Can take in a dummy parameter to use with iterate
(defn get-rand-byte 
	([] (get-rand-byte 0))
	([x] (- (rand-int 256) 128)))

;Generate a byte array of random bytes
;Use this to generate random AES keys and IVs
(defn get-rand-bytes [^Integer n]
	(->> (iterate get-rand-byte (get-rand-byte))
		 (take n)
		 (map byte)
		 (byte-array)))

;;;;;;;;;;;;;;;;;; CHALLENGE 17 ;;;;;;;;;;;;;;;;;;

;String and key constants for the challenge
(def challenge17-strings ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"])
(def const-key (get-rand-bytes CBC-KEYSIZE))

(defn rand-ele-from-coll [coll]
	(nth coll (rand-int (count coll))))

;Returns a vector of ciphertext and the IV
(defn c17-create-encrypted []
	(let [IV (get-rand-bytes CBC-KEYSIZE)]
		[(-> (rand-ele-from-coll challenge17-strings)
			 (Pad-PKCS7-Bytes CBC-KEYSIZE)
			 (encrypt-CBC const-key IV)), IV]))

;Sample decryption function - Will tell us if we can decrypt the ciphertext or not
(defn c17-decrypt [[ciphertext IV]]
	(try 
		(do (-> (decrypt-CBC ciphertext const-key IV)
			(valid-PKCS7-Padding?))
			true)
		(catch Exception e false)))

;Decrypts a block using a padding oracle attack
;Will backtrack if current decryption route is proving unsuccessful
;@Change-block - The block before the last block that we are changing values in to attack the last block
;@Last-block - The last block in the ciphertext that we are attacking
;@Prev-blocks - The previous blocks in the ciphertext - Needed for proper decryption
;@IV - The IV sent to the decryption function
(defn c17-oracle-decrypt-block [change-block last-block prev-blocks IV]
	(let [block-size (count IV)]	
	(loop [vals all-byte-values found () prev-bytes ()]
		(cond (= block-size (count found)) found
			  (empty? vals) (if (= nil (first prev-bytes)) nil
								(recur (drop-while #(not= (inc (first prev-bytes)) %) all-byte-values) (rest found) (rest prev-bytes)))
			  :else (let [found-count      (count found)
						  to-drop          (inc found-count) 
						  to-add           (map #(bit-xor %1 %2 to-drop) (take-last found-count change-block) found)
						  byte-to-test     (first vals)
				  	      new-change-block (concat (drop-last to-drop change-block) [byte-to-test] to-add)]
						(if (c17-decrypt [(barray (flatten (concat prev-blocks new-change-block last-block))) IV])
							(recur all-byte-values 
								  (conj found (bit-xor to-drop (last (drop-last found-count change-block)) byte-to-test)) 
                                  (conj prev-bytes byte-to-test))
							(recur (rest vals) found prev-bytes)))))))

;Use this function to decrypt just the first block - similar to above except it only needs the first block and the IV
(defn c17-oracle-decrypt-first-block [first-block IV]
	(let [block-size (count IV)]
		(loop [vals all-byte-values found () prev-bytes ()]
			(cond (= block-size (count found)) found
				  (empty? vals) (if (= nil (first prev-bytes)) nil
									(recur (drop-while #(not= (inc (first prev-bytes)) %) all-byte-values) (rest found) (rest prev-bytes)))
				  :else (let [found-count    (count found)
							  to-drop        (inc found-count) 
							  to-add         (map #(bit-xor %1 %2 to-drop) (take-last found-count IV) found)
							  byte-to-test   (first vals)
					  	      new-IV         (concat-bytes-to-array [(drop-last to-drop IV) [byte-to-test] to-add])]
							(if (c17-decrypt [first-block new-IV])
								(recur all-byte-values 
									  (conj found (bit-xor to-drop (last (drop-last found-count IV)) byte-to-test)) 
		                              (conj prev-bytes byte-to-test))
								(recur (rest vals) found prev-bytes)))))))

;This function is used to execute the padding attack
;Takes in the vector produced c17-create-encrypted as input
(defn c17-CBC-oracle [[ciphertext IV]]
	(loop [blocks (partition 16 ciphertext) result-blocks ()]
		(let [[change-block last-block] (take-last 2 blocks)
			  prev-blocks               (drop-last 2 blocks)]
			(if (= nil last-block) (->> (c17-oracle-decrypt-first-block change-block IV)
										(conj result-blocks)
										(map #(bytes-to-string %))
										(apply str))
				(recur (butlast blocks) (conj result-blocks (c17-oracle-decrypt-block change-block last-block prev-blocks IV)))))))

(defn test-challenge17 []
	(println "Testing challenge 17:")
	(let [encrypted-values     (c17-create-encrypted)
		  decrypted-result     (c17-CBC-oracle encrypted-values)
		  raw-decrypted-string (bytes-to-string (valid-PKCS7-Padding? decrypted-result))]
		(if (some #{raw-decrypted-string} challenge17-strings) 
			(println "Sucessfully achieved attack on string: " raw-decrypted-string)
			(println "Failed miserably"))))

;;;;;;;;;;;;;;;;;; CHALLENGE 18 ;;;;;;;;;;;;;;;;;;

;Challenge strings
(def c18-encrypted-str "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
(def c18-key "YELLOW SUBMARINE")
(def c18-nonce 0)

;Use this for making byte buffers for nonce generation
(import java.nio.ByteBuffer) 
(import java.nio.ByteOrder)

(defn ^bytes long-to-le-bytes [^Long n]
	(-> (ByteBuffer/allocate 8)
		(.order ByteOrder/LITTLE_ENDIAN)
		(.putLong n)
		(.array)))

(defn CTR-nonce-func [nonce-bytes block-num]
	(barray (concat nonce-bytes (long-to-le-bytes block-num))))

(defn CTR-keystream 
([key nonce]
	(CTR-keystream key (long-to-le-bytes nonce) 0))
([key nonce-bytes block-num]
	(cons (encrypt-ECB (CTR-nonce-func nonce-bytes block-num) key) (lazy-seq (CTR-keystream key nonce-bytes (inc block-num))))))

(defn encrypt-CTR [^bytes buf key nonce]
	(concat-bytes-to-array (pmap bit-xor-blocks (partition-all 16 (sanitize-str-bytes buf)) (CTR-keystream key nonce))))

(defn decrypt-CTR [^bytes buf key nonce]
	(encrypt-CTR buf key nonce))
	
(defn test-challenge18 []
	(println "Testing challenge 18:")
	(println "Can we decrypt the base64 encrypted string?")
	(println (String. (decrypt-CTR (base64-to-bytes c18-encrypted-str) c18-key c18-nonce)))
	(println "Can we decrypt/encrypt with a random nonce and random key?")
	(let [rand-key   (get-rand-bytes 16)
		  rand-nonce (rand-int Integer/MAX_VALUE)
		  test-str   "Winner(s) or The Winner(s) may refer to: Champion, the victor in a challenge or contest"]
		(println (= test-str (String. (decrypt-CTR (encrypt-CTR test-str rand-key rand-nonce) rand-key rand-nonce) "UTF-8")))))

;;;;;;;;;;;;;;;;;; CHALLENGE 19 ;;;;;;;;;;;;;;;;;;

(def c19-strs ["SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
			   "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
			   "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
			   "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
			   "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
			   "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
			   "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
			   "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
			   "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
			   "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
			   "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
			   "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
			   "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
			   "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
			   "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
			   "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
			   "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
			   "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
			   "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
			   "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
			   "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
			   "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
			   "U2hlIHJvZGUgdG8gaGFycmllcnM/",
			   "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
			   "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
			   "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
			   "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
			   "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
			   "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
			   "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
			   "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
			   "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
			   "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
			   "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
			   "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
			   "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
			   "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
			   "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
			   "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
			   "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="])
(def c19-str-bytes (map base64-to-bytes c19-strs))

(def c19-key (barray '(-91 -80 -53 -71 54 0 77 -99 120 41 -5 -41 -103 -61 66 100)))
(def c19-nonce 0)

(defn c19-CTR [buf] (encrypt-CTR buf c19-key c19-nonce))
(def c19-encrypted-strs (map c19-CTR c19-str-bytes))

(defn test-challenge19 []
	(println "Testing challenge 19:")
	(println "No automation for this test. Last line is A terrible beauty is born."))

;;;;;;;;;;;;;;;;;; CHALLENGE 20 ;;;;;;;;;;;;;;;;;;

(def c20-str-bytes (map base64-to-bytes  (read-lines "text/challenge20.txt")))
(def c20-nonce 0)
(def c20-key (get-rand-bytes 16))
(def c20-encrypted-strs (map #(encrypt-CTR % c20-key c20-nonce) c20-str-bytes))

;;;;;;; LOAD SOLUTIONS.CLJ TO GET OLD HEX XOR ATTACK
(load-file "solutions.clj")

;Returns the streams decrypted up to the length of the smallest stream
(defn c20-decrypt [encrypted-strs]
	(let [min-count (apply min (map count encrypted-strs))
		  concated-str (concat-bytes-to-array (map (partial take min-count) encrypted-strs))
		  encrypted-hex (clojure.string/lower-case (DatatypeConverter/printHexBinary concated-str))
		  keystream (find-key encrypted-hex min-count)]	
	(map #(String. % "UTF-8") (map #(bit-xor-blocks (DatatypeConverter/parseHexBinary (hexify keystream)) %) encrypted-strs))))

(defn test-challenge20 []
	(println "Testing challenge 20:")
	(println "Values from decryption of file is:")
	(println (c20-decrypt c20-encrypted-strs)))

;;;;;;;;;;;;;;;;;; CHALLENGE 21 ;;;;;;;;;;;;;;;;;;

;Define the internal array
;Note: Java does not have unsigned integers, but byte values returned are correct
;To get the unsigned representation, change MT to be an array of Longs
(def MT (make-array Integer/TYPE 624))
(def MT-index (atom 0))

;Unsigned right shift operator
(defn >>> [v bits] (bit-shift-right (bit-and 0xFFFFFFFF v) bits))

(defn init-MT 
([^Integer seed]
	(init-MT seed [MT MT-index]))
([^Integer seed [MT MT-index]]
	(aset MT 0 seed)
	(swap! MT-index (fn [x] 0))
	(loop [i 1]
		(if (= i 624) [MT MT-index]
			(let [prev-val (aget MT (dec i))]
				(aset MT i (bit-and (+ (* 1812433253 (bit-xor prev-val (>>> prev-val 30))) i) 0xffffffff))
				(recur (inc i)))))))

;Use this to generate a MT with a passable state
;We may want to have multiple MT for speed reasons
(defn generate-MT-state [^Integer seed]
	(init-MT seed [(make-array Integer/TYPE 624) (atom 0)]))

(defn generate-numbers-MT 
([]
	(generate-numbers-MT [MT MT-index]))
([[MT MT-index]]
	(loop [i 0]
		(if (= i 623) [MT MT-index]		
		(let [y (+ (bit-and (aget MT i) 0x80000000) (bit-and (aget MT (mod (inc i) 624)) 0x7fffffff))]
			(aset MT i (bit-xor (aget MT (mod (+ 397 i) 624)) (>>> y 1)))
			(when (not= 0 (mod y 2)) 
				(aset MT i (bit-xor (aget MT i) 0x9908b0df)))
				(recur (inc i)))))))

(defn ^Integer temper-MT [^Integer y]
	(->> y
	 (#(bit-xor % (>>> % 11)))
	 (#(bit-xor % (bit-and (bit-shift-left % 7) 0x9d2c5680)))
	 (#(bit-xor % (bit-and (bit-shift-left % 15) 0xefc60000)))
	 (#(bit-xor % (>>> % 18)))))

(defn ^Integer genrand-MT 
([]
	(genrand-MT [MT MT-index]))
([[MT MT-index]]
	(when (= 0 @MT-index) (generate-numbers-MT [MT MT-index]))
	
	(let [y (aget MT @MT-index)]
		(swap! MT-index #(mod (inc %) 624))
		(temper-MT y))))

(defn test-challenge21 []
	(println "Testing challenge 21:")
	(println "Call init-MT with a seed and then genrand-MT to generate numbers using the MT19937 Mersenne Twister RNG"))

;;;;;;;;;;;;;;;;;; CHALLENGE 22 ;;;;;;;;;;;;;;;;;;

;Waits inbetween a certain number of seconds
(defn wait-rand-seconds [min max]
	(let [wait-time (* 1000 (+ (rand-int (- max min)) min))]
		(. Thread (sleep wait-time))))

;Unix timestamp - sourced from http://stackoverflow.com/questions/732034/getting-unixtime-in-java
(defn unix-timestamp [] (long (/ (. System (currentTimeMillis)) 1000)))

;Min and max wait times
(def c22-wait-min 40)
(def c22-wait-max 1000)

;Generate a random number to break as defined by challenge
(defn c22-generate-rand-number [mint maxt]
	(wait-rand-seconds mint maxt)
	(let [seed-value (unix-timestamp)]	
		(init-MT seed-value)
		(wait-rand-seconds mint maxt)
		(let [result (genrand-MT)]
			(println "Done generating value. Seed is" seed-value)
			result)))

(defn find-time-seed [num]
	(loop [current-stamp (unix-timestamp)]
		(init-MT current-stamp)
		(let [test-num (genrand-MT)]
			(cond (= test-num num) current-stamp
				  (= current-stamp 0) nil
				  :else (recur (dec current-stamp))))))

;Works but test with low numbers to save some time
;Replace (c22-generate-rand-number 0 3) with (c22-generate-rand-number c22-wait-min c22-wait-max) for long challenge test
(defn test-challenge22 []
	(println "Testing challenge 22:")
	(let [rand-number (c22-generate-rand-number 0 3)]
		(println "Found seed value" (find-time-seed rand-number))))

;;;;;;;;;;;;;;;;;; CHALLENGE 23 ;;;;;;;;;;;;;;;;;;

;If the MT19937 generate had the outputs subjected to a cryptographic hash it would make this approach
;unfeasible, since cryptographic hashes are one-way functions.

;Reverse the tempering function
(defn ^Integer untemper-MT [^Integer n]
	(->> n
		(#(bit-xor % (>>> % 18)))
		(#(bit-xor % (bit-and (bit-shift-left % 15) 0xefc60000)))
		(repeat 5)
		(reduce #(bit-xor %2 (bit-and (bit-shift-left %1 7) 0x9d2c5680)))
		(repeat 3)
		(reduce #(bit-xor %2 (>>> %1 11)))))

;Copies the MT internal array - assumes at start of array
;Pass in seed to re-initialize 
(defn copy-MT-state 
([seed]
	(init-MT seed)
	(copy-MT-state))
([]
	(for [x (range 624)]
		(untemper-MT (genrand-MT)))))


(defn test-challenge23 []
	(println "Testing challenge 23:")
	(println "Can we properly untemper MT19937?")
	(println (let [rand-val (rand-int 2000000)] (= rand-val (untemper-MT (temper-MT rand-val)))))
	(println "Can we copy the MT state?")
	(println (let [copied (copy-MT-state (rand-int 100000))]
			 (= (genrand-MT [(int-array copied) (atom 0)]) (genrand-MT)))))

;;;;;;;;;;;;;;;;;; CHALLENGE 24 ;;;;;;;;;;;;;;;;;;

;Const string for testing
(def c24-str "Ain't nobody dope as me I'm dressed so fresh so clean")

(defn ^bytes int-to-bytes [n]
	(-> (ByteBuffer/allocate 4)
		(.order ByteOrder/BIG_ENDIAN)
		(.putInt (.intValue n))
		(.array)))

(defn MT-keystream 
([]
	(map int-to-bytes (repeatedly genrand-MT)))
([MT-state]
	(map int-to-bytes (repeatedly #(genrand-MT MT-state)))))

;Assume key is 16-bit numerical value, so smaller than 65536
;Pass in either string or byte array
(defn ^bytes MT-encrypt [buf ^Integer key]
	(let [partitioned-bytes (partition-all 4 (sanitize-str-bytes buf))
		  MT-state (generate-MT-state key)]
		(concat-bytes-to-array (map bit-xor-blocks partitioned-bytes (MT-keystream MT-state)))))

(defn ^String MT-decrypt [buf ^Integer key]
	(let [partitioned-bytes (partition-all 4 (sanitize-str-bytes buf))
		  MT-state (generate-MT-state key)]
		(->> (map bit-xor-blocks partitioned-bytes (MT-keystream MT-state))
			 (concat-bytes-to-array)
			 (bytes-to-string))))

;Rand values are constant on file load - to test decryption of file after finding seed
(def c24-rand-val (rand-int 65536))
(def c24-rand-bytes (get-rand-bytes 100))

;Creates a string encrypted with a random 16-bit seed as specified in the challenge
(defn c24-rand-encrypted-str [known-str]
	(let [test-str (str (String. c24-rand-bytes "UTF-8") known-str)]
		(MT-encrypt test-str c24-rand-val)))

;Create a str encrypted with time seed
(defn c24-time-encrypted-str [known-str]
	(let [test-str (str (String. c24-rand-bytes "UTF-8") known-str)
		  seed (- (unix-timestamp) 1000)]
		(println "Encrypting with seed" seed)
		(MT-encrypt test-str seed)))

;Currently extremely slow - we could speed up by pregenerating all MT-initial states for the first 2^16 numbers
;If not passed in seed values this function will test the first 16 bit values
(defn c24-determine-rand-seed 
([encrypted-str known-str]
	(c24-determine-rand-seed encrypted-str known-str 65536 0))
([encrypted-str known-str seed]
	(c24-determine-rand-seed encrypted-str known-str seed (- seed 65536)))
([encrypted-str known-str seed start-seed]
	(loop [i seed]
		(cond (= i start-seed) nil
			  (.contains (MT-decrypt encrypted-str i) known-str) (do (println "Found value:" i))
			  :else (do (when (= (mod i 100) 0) (println "At " i))
					    (recur (dec i)))))))


(def chunk-size 124)

;Same as method above but runs in parallel chunks instead of sequentially - some speedup
(defn c24-determine-rand-seed-parallel
([encrypted-str known-str]
	(c24-determine-rand-seed-parallel encrypted-str known-str 65536 0))
([encrypted-str known-str seed]
	(c24-determine-rand-seed-parallel encrypted-str known-str seed (- seed 65536)))
([encrypted-str known-str seed start-seed]	
	(loop [i seed iterations 0]
		(let [min-bound (max (- i chunk-size) start-seed)]
	    (if (= i start-seed) nil
		    (let [found? (->> (range min-bound (inc i))
							  (pmap #(.contains (MT-decrypt encrypted-str %) known-str))
							  (indices true?)
							  (first))]
				 (if (not= nil found?) (- (- seed (* iterations chunk-size)) found?)
					 (do (println "At " i)
                         (recur (- i chunk-size) (inc iterations))))))))))

(defn test-challenge24 []
	(println "Testing challenge 24:")
	(println "Do we have a proper MT cipher?")
	(println (let [rand-val (rand-int 65536)
				   test-str (str (String. (get-rand-bytes 100)) c24-str)]
				(= test-str (MT-decrypt (MT-encrypt test-str rand-val) rand-val))))
	(println "Can we break a random 16-bit seed? (WARNING: SLOW)")
	(println (not= nil (c24-determine-rand-seed-parallel (c24-rand-encrypted-str c24-str) c24-str)))) 

;;;;;;;;;;;;;;;;;; TEST ALL SOLUTIONS IN FILE ;;;;;;;;;;;;;;;;;;

;Call this to test challenges 17-24

(defn test-all []
	(test-challenge17)
	(test-challenge18)
	(test-challenge19)
	(test-challenge20)
	(test-challenge21)
	(test-challenge22)
	(test-challenge23)
	(test-challenge24))



