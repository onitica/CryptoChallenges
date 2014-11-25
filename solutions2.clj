;;;;; UTILITY FUNCTIONS AND DEFINITIONS

;Use this for converting Java data to bytes
(import javax.xml.bind.DatatypeConverter)

(defn base64-to-bytes [^String s]
	(DatatypeConverter/parseBase64Binary s))

;Concatenate different collections and then turn them into a str
(defn strcat [& args]
	(apply str (apply concat args)))

;Read a file into a vector of lines
(defn read-file-into-buffer [f]
	(clojure.string/replace (slurp f) #"\n" ""))

;Convenience function for casting colls to byte arrays
(defn barray [coll]
	(byte-array (map byte coll)))

(defn bytes-to-string [coll]
	(String. (barray coll) "UTF-8"))

(defn concat-bytes-to-array [b]
	(barray (apply concat b)))

;Remove first and last elements in collection
(defn peel [coll]
	(-> coll (butlast) (rest)))

(def all-byte-values (map #(- % 128) (range 256)))

;;;;;;;;;;;;;;;;;; CHALLENGE 9 ;;;;;;;;;;;;;;;;;;

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

(defn test-challenge9 []
	(println "Testing challenge 9:")
	(println "Can we PKCS7 pad like a boss?")
	(println (= (Pad-PKCS7-String "I PAD LIKE A BOSS" 100) "I PAD LIKE A BOSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS")))

;;;;;;;;;;;;;;;;;; CHALLENGE 15 ;;;;;;;;;;;;;;;;;;

;In the order of challenges - this really belongs here and is necessary to complete earlier challenges

;Must take in either string or bytes -> returns a collection if valid or else throws an exception
;Methodology -> Reverse block, take while the bytes are equal, check if all the bytes are equal to the length of the equal bytes
(defmulti valid-PKCS7-Padding? class)
(defmethod valid-PKCS7-Padding? String [s] (valid-PKCS7-Padding? (.getBytes s)))
(defmethod valid-PKCS7-Padding? (Class/forName "[B") [block] 
	(let [end-repeats (take-while #(= (last block) %) (reverse block))
		  pad (count end-repeats)]
		(if (apply = pad end-repeats)
			(drop-last pad block)
			(throw (Exception. "Bad Padding Exception")))))

;Call this to throw exception (valid-PKCS7-Padding? "ICE ICE BABY109")
(defn test-challenge15 []
	(println "Testing challenge 15:")
	(println "Can we detect valid PKCS7-Padding?")
	(println (and (= (bytes-to-string (valid-PKCS7-Padding? (Pad-PKCS7-String "ICE ICE BABY" 16))) "ICE ICE BABY")
				  (= (bytes-to-string (valid-PKCS7-Padding? (Pad-PKCS7-String "ICE ICE BABY" 17))) "ICE ICE BABY"))))
;;;;;;;;;;;;;;;;;; CHALLENGE 10 ;;;;;;;;;;;;;;;;;;

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

;This example line would solve challenge7
;(decrypt-ECB (base64-to-bytes (read-file-into-buffer "text/challenge7.txt")) "YELLOW SUBMARINE")

;Use this to bit-xor two equal size collections of byte blocks
;Returns an array of byte blocks
(defn ^bytes bit-xor-blocks [^bytes b1 ^bytes b2]
	(barray (map bit-xor b1 b2)))

(def CBC-KEYSIZE 16)
(def EMPTY-IV (barray (repeat 16 0)))

(defn first-block [b] (take CBC-KEYSIZE b))
(defn rest-buf [b] (drop CBC-KEYSIZE b))

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
				  :else (recur (first-block rem) (rest-buf rem) b start)))))

;Wrapper around decrypt CBC function to retun a string
(defn ^String decrypt-CBC-String [^bytes buf key ^bytes IV]
	(String. (decrypt-CBC buf key IV) "UTF-8"))

(defn test-challenge10 []
	(println "Testing challenge 10:")
	(println "Can we properly decrypt and encrypt CBC?")
	(let [text "YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"
		  key "I LIKE CANDY LOL"
		  enc1 (encrypt-CBC (.getBytes text) key EMPTY-IV)]
		(println (= (decrypt-CBC-String enc1 key EMPTY-IV) text))))

(defn test-gistfile-challenge10 []
	(decrypt-CBC-String (base64-to-bytes (read-file-into-buffer "text/challenge10.txt")) "YELLOW SUBMARINE" EMPTY-IV))

;;;;;;;;;;;;;;;;;; CHALLENGE 11 ;;;;;;;;;;;;;;;;;;

;Generate random byte
;Can take in a dummy parameter to use with iterate
(defn get-rand-byte 
	([] (get-rand-byte 0))
	([x] (- (rand-int 256) 128)))

(defn rand-bool [] (= 0 (rand-int 2)))

;Generate a byte array of random bytes
;Use this to generate random AES keys and IVs
(defn get-rand-bytes [^Integer n]
	(->> (iterate get-rand-byte (get-rand-byte))
		 (take n)
		 (map byte)
		 (byte-array)))

;Attaches 5-10 random bytes before and after the given bytes
;Then PKCS7 pads the bytes so that they can be encrypted/decrypted and then returns a byte array
(defn rand-padding [^bytes b]
	(let [r1 (get-rand-bytes (+ (rand-int 6) 5))
		  r2 (get-rand-bytes (+ (rand-int 6) 5))]
		(barray (Pad-PKCS7 (barray (concat r1 b r2)) CBC-KEYSIZE))))

;Encryption oracle function
(defn encryption-oracle [^String s]
	(let [buf (rand-padding (.getBytes s))]
		(if (rand-bool) (encrypt-CBC buf (get-rand-bytes 16) (get-rand-bytes 16))
						(encrypt-ECB buf (get-rand-bytes 16)))))

;Cleanup and generilization of code from previous solution file
(defn ^Integer char-length-repeats [^bytes s ^Integer n]
		(let [repeats (->> (partition n s)
			 			(group-by identity)
			 			(vals)
						(map count)
						(filter (partial < 2)))
			  score (if (empty? repeats) 0 (reduce + repeats))]
			score))

;Determine if is ECB encrypted bytes
(defn is-ecb-encrypted [^bytes s]
	(if (> (char-length-repeats s 16) 0) true false))

;Test for ecb encryption example
;(is-ecb-encrypted (encryption-oracle (apply str (repeat 64 \A))))

(defn test-challenge11 []
	(println "Testing challenge 11:")
	(println "Just have to run it in code!"))

;;;;;;;;;;;;;;;;;; CHALLENGE 12 ;;;;;;;;;;;;;;;;;;

(def const-key (get-rand-bytes 16))
(def base64str-bytes (base64-to-bytes "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"))

(defn c12-oracle [s]
	(let [prebuf (if (= String (class s)) (.getBytes s) s)
		  buf (Pad-PKCS7-Bytes (concat prebuf base64str-bytes) CBC-KEYSIZE)]
		(encrypt-ECB buf const-key)))

;a) Use this function to determine keysize
(defn determine-block-size [oraclefunc]
	(let [output-count (comp count oraclefunc)
		  base-count (output-count "")]
		(loop [test-str "A"]
			(let [diff (- (output-count test-str) base-count)]
				(if (> diff 0) diff (recur (str test-str "A")))))))

;b) Use this to determine ECB encryption
;(is-ecb-encrypted (c12-oracle (apply str (repeat 64 \A))))

;Answer to part c)
(defn keysize-minus1-block [^Integer keysize]
	(repeat (- keysize 1) 50))

;Generate a random stream of prefix bytes to make chance the prefix generates a false positive extremely low while keeping it consistent between calls
(def prefix-random-byte-source (get-rand-bytes 256))

;Input keysize-1 to this function to generate -1 byte length
(defn gen-prefix 
([^Integer size]
	(gen-prefix size []))
([^Integer size ^bytes endBytes]
	(let [diff (- size (count endBytes))]
		(concat (take diff prefix-random-byte-source) endBytes))))

;Helper function to cleanup code
;Takes in a collection, casts it to a byte array, passes it to the encryption oracle and returns the requested block as a vector
;@coll - The collection of bytes to pass to the oracle function
;@keysize - The keysize of the oracle function
;@oraclefunc - The actual oracle functions
;@bytes-todrop - the amount of bytes to drop when finding the block
(defn find-oracle-block 
([coll keysize oraclefunc]
	(find-oracle-block coll keysize oraclefunc 0))
([coll keysize oraclefunc bytes-todrop]
	(->> coll
		 (barray)
		 (oraclefunc)
		 (drop bytes-todrop)
		 (take keysize)
		 (into []))))

;Answer to part d)
;Creates a dictionary where the key is the oracle encryption value and the key is the byte value
;Different overloads depending on what information is needed to be given (inputs have same meaning as the find-oracle-block function)
(defn oracle-dictionary 
([^Integer keysize]
	(oracle-dictionary keysize (keysize-minus1-block keysize)))
([^Integer keysize ^bytes coll]
	(oracle-dictionary keysize coll c12-oracle))
([^Integer keysize ^bytes coll oraclefunc]
	(oracle-dictionary keysize coll oraclefunc 0))
([^Integer keysize ^bytes coll oraclefunc ^Integer bytes-todrop]
	(let [pre-bytes (into [] coll)]
		(into {} 
			(for [x all-byte-values] [(find-oracle-block (conj pre-bytes x) keysize oraclefunc bytes-todrop) x])))))

;Answer to parts e and f
;Pass in the oracle function to solve it
(defn c12-decrypt-oracle [oraclefunc]
	(let [keysize (determine-block-size oraclefunc)
		  maxprefixsize (dec keysize)
		  todrop (fn [x] (* keysize (quot x keysize)))]
		(loop [result []]
			(cond (and (nil? (last result)) (not (empty? result))) (drop-last result)
				  :else (let [oracle-prefix (gen-prefix (- maxprefixsize (rem (count result) keysize)))
							  search-prefix (gen-prefix maxprefixsize (take-last maxprefixsize result))
							  oracle-dict (oracle-dictionary keysize search-prefix)]
							(recur (conj result (oracle-dict (find-oracle-block oracle-prefix keysize oraclefunc (todrop (count result)))))))))))

(defn test-challenge12 []
	(println "Testing challenge 12:")
	(println "Can we determine the key length?")
	(println (= CBC-KEYSIZE (determine-block-size c12-oracle)))
	(println "Can we determine if the oracle is using ECB?")
	(println (is-ecb-encrypted (c12-oracle (apply str (repeat 64 \A)))))
	(println "Can we decrypt using this oracle function?")
	(println (String. (barray (c12-decrypt-oracle c12-oracle)))))

;;;;;;;;;;;;;;;;;; CHALLENGE 13 ;;;;;;;;;;;;;;;;;;

(def c13-encoded-str "foo=bar&baz=qux&zap=zazzle")
(def test-profile-for "{\n\tfoo: 'bar&admin=cool',\n\tbaz: 'qux',\n\tzap: 'zazzle'\n}")

(defn partial-JSON-encode [^String encoded]
	(let [pairs (partition 2 (clojure.string/split encoded #"[\&\=]"))
		  JSON-pairs (map (fn [[a b]] (str \tab a ": '" b \')) pairs)]
		(str "{\n" (apply str (interpose ",\n" JSON-pairs)) "\n}")))

(defn partial-JSON-decode [^String JSON]
	(->> (clojure.string/split JSON #"[ \t\n\:\'\,]+")
		 (peel)
		 (map #(apply str (remove #{\& \=} %)))
		 (partition 2)
		 (map (fn [[a b]] (str a \= b)))
		 (interpose \&)
		 (apply str)))

(def c13-id (atom 0))

(defn profile-for [^String user]
	(let [id (swap! c13-id inc)
		  escaped-str (clojure.string/replace user #"[ \t\n\:\'\,]+" "")]
		(partial-JSON-decode (str "{\n\tuser:" escaped-str "',\n\tuid: " id ",\n\trole: 'user'\n}"))))

(defn encrypt-c13 [^String profile]
	(encrypt-ECB (Pad-PKCS7-Bytes (.getBytes profile) CBC-KEYSIZE) const-key))

(defn decrypt-c13 [^String encrypted]
	(bytes-to-string (valid-PKCS7-Padding? (decrypt-ECB encrypted const-key))))

;To figure this out - we need to look at the structure of what is encoded
;We need to generate a profile that will simply have user padded in the last block, and replace it with a block that has admin padded to the end

;First determine block size
(def c13-block-size (determine-block-size encrypt-c13))

;Determine what admin encrypted would look like
(def admin-padded-block (Pad-PKCS7-String "admin" c13-block-size))

;Pass it in with 11 bytes prepended to the block - so we can guarantee the admin encrypted block is encrypted entirely as the second block
(def admin-encrypted-block (take 16 (drop 16 (encrypt-c13 (profile-for (str "AAAAAAAAAAA" admin-padded-block))))))

;Create the profile with role=admin
;Easily do this by passing in increasing block sizes, replacing the last block with the encrypted admin block, until we get what we want
;We must do it this way if we do not know the length of the intermediate bytes (i.e. how long uid will be)
(defn c13-create-good-profile []
	(loop [test "a"]
		(let [attack-attempt (decrypt-c13 (barray (concat (drop-last 16 (encrypt-c13 (profile-for test))) admin-encrypted-block)))]
			(if (= (apply str (take-last 10 attack-attempt)) "role=admin") attack-attempt (recur (str test "a"))))))

(defn test-challenge13 []
	(println "Testing challenge 13:")
	(println "Can we generate a profile with role=admin?")
	(println (c13-create-good-profile)))

;;;;;;;;;;;;;;;;;; CHALLENGE 14 ;;;;;;;;;;;;;;;;;;

;This is the case where the random prefix is a different length every time
;Define a random-prefix that is constant length
(def random-prefix-const (get-rand-bytes (+ (rand-int 30) 2)))

;In this case I'm assuming that the random-prefix before my attack is always the same amount of bytes
(defn c14-oracle [s]
	(let [prebuf (if (= String (class s)) (.getBytes s) s)
		  buf (Pad-PKCS7-Bytes (concat random-prefix-const prebuf base64str-bytes) CBC-KEYSIZE)]
		(encrypt-ECB buf const-key)))

;This function will tell me the index first block in the oracle where passing an input will change the outcome of the encryption
(defn block-to-attack
([^Integer keysize ^bytes pad-bytes oraclefunc]
	(let [pre-bytes (into [] pad-bytes)]
		(loop [todrop 0]
			(if (apply = (for [x [\A \B]] (find-oracle-block (conj pre-bytes x) keysize oraclefunc (* todrop keysize))))
				(recur (inc todrop))
				todrop)))))

;This function generates the values we need to overcome the random prefix
;Returns a vector - The first value indicates the length of padding to add to the start of my padding-oracle attack to stretch the random prefix to 
;equal a block size. The second value indicates how many previous blocks to drop in attack functions (like generating my oracle dictionary)
(defn determine-attack-padding-and-block [keysize oraclefunc]
	(let [initial-block-to-attack (block-to-attack keysize [] oraclefunc)]	
		(loop [attemptcount 1]
			(if (= attemptcount (inc keysize))
				[0 0]
				(let [attempt (block-to-attack keysize (repeat attemptcount 0) oraclefunc)]
					(if (> attempt initial-block-to-attack) 
						[attemptcount attempt]
						(recur (inc attemptcount))))))))

;A modified version of the function for challenge 12 - but takes into account the random-prefix
(defn c14-decrypt-oracle [oraclefunc]
	(let [keysize (determine-block-size oraclefunc)
		  attack-vector (determine-attack-padding-and-block keysize oraclefunc)
		  prefix-extender (first attack-vector)
		  bytes-todrop (* keysize (second attack-vector))
		  maxprefixsize (dec keysize)
		  todrop (fn [x] (+ bytes-todrop (* keysize (quot x keysize))))]
		(loop [result []]
			(cond (and (nil? (last result)) (not (empty? result))) (drop-last result)
				  :else (let [oracle-prefix (gen-prefix (+ prefix-extender (- maxprefixsize (rem (count result) keysize))))
							  search-prefix (gen-prefix (+ prefix-extender maxprefixsize) (take-last maxprefixsize result))
							  oracle-dict (oracle-dictionary keysize search-prefix c14-oracle bytes-todrop)]
							(recur (conj result (oracle-dict (find-oracle-block oracle-prefix keysize oraclefunc (todrop (count result)))))))))))

(defn test-challenge14 []
	(println "Testing challenge 14:")
	(println "Can we decrypt a oracle that has a random prefix attached to it?")
	(println (String. (barray (c14-decrypt-oracle c14-oracle)))))

;;;;;;;;;;;;;;;;;; CHALLENGE 16 ;;;;;;;;;;;;;;;;;;

;Thoughts on 1-bit error property
;We could possibly correct the previous ciphertext block from the decryption of the next block. If the edit in the next
;block is out of place in an obvious way (assuming we have encoded data that is contextually relevant and not just noise), we
;could figure out what byte in the ciphertext was wrong and fix the ciphertext to get the proper decoding for the previous block.
;A way to add error correction in the ciphertext for if it suffers minor corruption before decryption.

(def prepend-data "comment1=cooking%20MCs;userdata=")
(def append-data ";comment2=%20like%20a%20pound%20of%20bacon")

(defn create-data-str [s]
	(str 
		prepend-data
		(-> s (clojure.string/replace #";" "%3B") (clojure.string/replace #"=" "%3D"))
		append-data))

(defn c16-create-encrypted-message [s]
	(-> (create-data-str s)
		(Pad-PKCS7-Bytes CBC-KEYSIZE)
		(encrypt-CBC const-key EMPTY-IV)))

(defn c16-decrypt-message [s]
	(barray (valid-PKCS7-Padding? (decrypt-CBC s const-key EMPTY-IV))))

(defn c16-admin-check [s]
	(.contains s ";admin=true;"))

(def c16-message-to-inject "junk16bytesplaya")
(def c16-message-we-want "aaaaa;admin=true")

;This is the xor data of the string we pass into the function and the string we want. This value xored by the string we passed in will
;give us the value we want
(def c16-xored-messages (bit-xor-blocks (.getBytes c16-message-to-inject) (.getBytes c16-message-we-want)))

;Encrypt using the injection data
(def c16-ciphertext (c16-create-encrypted-message c16-message-to-inject))

;We need the cipehrtext of the block we are injecting. We need to xor what we are injecting against this to get the CBC algorithm to generate the original injection string.
(def c16-attack-block-ciphertext (take 16 (drop 16 c16-ciphertext)))

(def converted-c16-ciphertext (concat (take 16 c16-ciphertext) (bit-xor-blocks c16-attack-block-ciphertext c16-xored-messages) (drop 32 c16-ciphertext)))

(defn test-challenge16 []
	(println "Testing challenge 16:")
	(println "Can we edit the ciphertext block to contain an admin=true message?")
	(println (String. (c16-decrypt-message converted-c16-ciphertext)))
	(println (c16-admin-check (String. (c16-decrypt-message converted-c16-ciphertext)))))

;;;;;;;;;;;;;;;;;; TEST ALL SOLUTIONS IN FILE ;;;;;;;;;;;;;;;;;;

;Call this to test challenges 9-16 

(defn test-all []
	(test-challenge9)
	(test-challenge10)
	(test-challenge11)
	(test-challenge12)
	(test-challenge13)
	(test-challenge14)
	(test-challenge15)
	(test-challenge16))






