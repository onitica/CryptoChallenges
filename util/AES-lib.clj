;;Contains implementations of AES EBC, CBC, and CTR modes
;;Also contains useful functions for dealing with cryptostreams

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
		      (coll? s) (barray s)
	          :else (throw (Exception. "Must pass in either a string, byte array, or collection to sanitize-str-bytes fn!")))))

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

;;;;;;;;;;;;;;;;;; PKCS7 Padding ;;;;;;;;;;;;;;;;;;

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

;;;;;;;;;;;;;;;;;; ECB Mode ;;;;;;;;;;;;;;;;;;

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

;;;;;;;;;;;;;;;;;; CBC Mode ;;;;;;;;;;;;;;;;;;

;Use this to bit-xor two equal size collections of byte blocks
;Returns an array of byte blocks
(defn ^bytes bit-xor-blocks [^bytes b1 ^bytes b2]
	(barray (map bit-xor b1 b2)))

(def AES-BLOCKSIZE 16)
(def EMPTY-BLOCK (barray (repeat AES-BLOCKSIZE 0)))
(def EMPTY-IV EMPTY-BLOCK)

(defn first-block [b] (take AES-BLOCKSIZE b))
(defn rest-buf [b] (drop AES-BLOCKSIZE b))
(defn last-block [b] (take-last AES-BLOCKSIZE b))
(defn drop-last-block [b] (drop-last AES-BLOCKSIZE b))

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

;;;;;;;;;;;;;;;;;; CTR Mode ;;;;;;;;;;;;;;;;;;

;Use this for making byte buffers for nonce generation
(import java.nio.ByteBuffer)
(import java.nio.ByteOrder)

(defn ^bytes long-to-le-bytes [^Long n]
	(-> (ByteBuffer/allocate 8)
		(.order ByteOrder/LITTLE_ENDIAN)
		(.putLong n)
		(.array)))

(def EMPTY-NONCE 0)

(defn CTR-nonce-func [nonce-bytes block-num]
	(barray (concat nonce-bytes (long-to-le-bytes block-num))))

(defn CTR-keystream
([key nonce]
	(CTR-keystream key (long-to-le-bytes nonce) 0))
([key nonce-bytes block-num]
	(cons (encrypt-ECB (CTR-nonce-func nonce-bytes block-num) key) (lazy-seq (CTR-keystream key nonce-bytes (inc block-num))))))

(defn encrypt-CTR [buf key nonce]
	(concat-bytes-to-array (pmap bit-xor-blocks (partition-all 16 (sanitize-str-bytes buf)) (CTR-keystream key nonce))))

(defn decrypt-CTR [buf key nonce]
	(encrypt-CTR buf key nonce))


