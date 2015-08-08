;; ctr-hash-drbg.lisp -- Counter Hash DRGB
;; DM/Acudora  06/12
;; -------------------------------------------------------------

(in-package :ecc-crypto-b571)

;; ------------------------------------------------------------------------

(defstruct ctr-hash-drbg-state
  seed key reseed ctr hash)

(defun random-key-256 ()
  (convert-int-to-nbytesv (basic-random-between 0 (ash 1 256)) 32))

#+:WIN32
(defun get-entropy (nb)
  ;; needs a source of entropy
  (random-key-256))

#+:MAC
(defun get-entropy (nb)
  (let ((ent (make-ub-array nb)))
    (with-open-file (fp "/dev/random"
                        :direction :input
                        :element-type 'ubyte)
      (read-sequence ent fp))
    ent))

(defmethod reseed-ctr-hash-drbg ((state ctr-hash-drbg-state))
  (with-accessors ((key    ctr-hash-drbg-state-key)
                   (reseed ctr-hash-drbg-state-reseed)) state
    (setf key    (get-entropy 32)
          reseed (ash 1 24)) ))

(defun make-new-ctr-hash-drbg-state ()
  (let* ((state (make-ctr-hash-drbg-state
                 :seed   (random-key-256)
                 :ctr    (convert-bytes-to-int (make-nonce))
                 :hash   (ironclad:make-digest :sha256)) ))
    (reseed-ctr-hash-drbg state)
    state))

(def-cached-var ctr-hash-drbg-state
  (make-new-ctr-hash-drbg-state))

;; --------------------------------------------------

(defmethod next-ctr-hash-drbg-block ((state ctr-hash-drbg-state))
  (with-accessors ((reseed ctr-hash-drbg-state-reseed)
                   (seed   ctr-hash-drbg-state-seed)
                   (key    ctr-hash-drbg-state-key)
                   (hash   ctr-hash-drbg-state-hash)
                   (ctr    ctr-hash-drbg-state-ctr)) state
    (labels ((generate-block ()
               (incf ctr)
               (let ((cvec (convert-int-to-nbytesv ctr 16)))
                 (reinitialize-instance hash)
                 (ironclad:update-digest hash key)
                 (ironclad:update-digest hash seed)
                 (ironclad:update-digest hash cvec)
                 (setf seed (ironclad:produce-digest hash)))))
      
      (unless (plusp (decf reseed))
        (reseed-ctr-hash-drbg state))
      
      (generate-block))))

(defstruct ctr-hash-drbg-buf
  (buf  (make-ub-array 512))
  (nb   0)
  (put  0)
  (get  0)
  (lock (mp:make-lock)))

(def-cached-var ctr-hash-drbg-buf
  (make-ctr-hash-drbg-buf))

(defmethod put-ctr-hash-drbg-buf ((db ctr-hash-drbg-buf) src)
  (with-accessors  ((buf    ctr-hash-drbg-buf-buf)
                    (put-ix ctr-hash-drbg-buf-put)
                    (navail ctr-hash-drbg-buf-nb)
                    (lock   ctr-hash-drbg-buf-lock)) db
    (let ((buflen (length buf)))
      (um:nlet-tail iter ((nb    (length src))
                          (start 0))
        (when (plusp nb)
          (if (< navail buflen)
              (let* ((nel (min nb
                               (- buflen navail)
                               (- buflen put-ix))))
                (replace buf src
                         :start1 put-ix :end1 (+ put-ix nel)
                         :start2 start  :end2 (+ start nel))
                (mp:with-lock (lock)
                  (incf navail nel)
                  (setf put-ix (mod (+ put-ix nel) buflen)))
                (iter (- nb nel) (+ start nel)))
            ;; else
            (progn
              (mp:process-wait "Waiting to replace entropy"
                               (lambda ()
                                 (< navail buflen)))
              (iter nb start)) ))) )))

(defun make-ctr-hash-drbg-thread ()
  (mp:process-run-function "CTR-HASH-DRBG Thread" nil
                           (lambda ()
                             (loop do
                                   (put-ctr-hash-drbg-buf (ctr-hash-drbg-buf)
                                            (next-ctr-hash-drbg-block (ctr-hash-drbg-state))) ))))

(def-cached-var ensure-ctr-hash-drbg-thread
  (make-ctr-hash-drbg-thread))

(defmethod get-ctr-hash-drbg-buf ((db ctr-hash-drbg-buf) nb)
  (ensure-ctr-hash-drbg-thread)
  (with-accessors ((buf    ctr-hash-drbg-buf-buf)
                   (navail ctr-hash-drbg-buf-nb)
                   (get-ix ctr-hash-drbg-buf-get)
                   (lock   ctr-hash-drbg-buf-lock)) db
    (let* ((buflen (length buf))
           (dst    (make-ub-array nb)))
      
      (um:nlet-tail iter ((nb    nb)
                          (start 0))
        (if (plusp nb)
            (if (plusp navail)
                  (let* ((nel (min nb navail
                                   (- buflen get-ix))))
                    (replace dst buf
                             :start1 start  :end1 (+ start nel)
                             :start2 get-ix :end2 (+ get-ix nel))
                    (mp:with-lock (lock)
                      (setf get-ix (mod (+ get-ix nel) buflen))
                      (decf navail nel))
                    (iter (- nb nel) (+ start nel)))
                ;; else
                (progn
                  (mp:process-wait "Waiting for more entropy"
                                   (lambda ()
                                     (plusp navail)))
                  (iter nb start)) )))
      dst)))

(defun ctr-hash-drbg (nbits)
  ;; NIST Hash DRBG
  (let ((ans (get-ctr-hash-drbg-buf (ctr-hash-drbg-buf) (ceiling nbits 8))))
    (mask-off ans (rem nbits 8)) ))

#|
(defun ctr-hash-drbg-int (nbits)
  (convert-bytes-to-int (ctr-hash-drbg nbits)))
|#

(unless (fboundp 'ctr-drbg)
  (setf (symbol-function 'ctr-drbg)  #'ctr-hash-drbg))

#|
(let* ((pts (loop repeat 10000 collect
                  (list (ctr-hash-drbg-int 16)
                        (ctr-hash-drbg-int 16))))
       (xs (mapcar #'first pts))
       (ys (mapcar #'second pts)))
  (plt:plot 'plt xs ys
            :clear t
            :symbol :dot))
|#

#|
(defun tst ()
  (let ((x (coerce
            (loop for ix from 1 to (ash 1 17) collect
                  (- (ctr-hash-drbg-int 8) 128))
            'vector)))
    (plt:plot 'plt (fft:fwd-magnitude-db x) :clear t)
    (plt:plot 'plt2 (map 'vector #'realpart
                         (fft:inv (map 'vector (lambda (x)
                                                 (* x (conjugate x)))
                                       (fft:fwd x))))
              :clear t
              :xrange '(-40 40)
              :yrange '(-5e7 5e7)
              )
    (subseq x 0 500)
    ))
|#