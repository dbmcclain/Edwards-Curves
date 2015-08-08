# Edwards-Curves
Edwards Curves in Lisp

For anyone interested, I have written an implementation of Edwards Curves over the prime fields, curves from the SafeCurves list known as Curve1174 (251 bits), Curve 41417 (414 bits), and Curve-E521 (521 bits). The package also contains Elligator-1 and Elligator-2 encode / decode for mapping points over the Elliptic Curves to uniformly random numbers for use in ECDH key exchange, and for generating Schnorr Signatures.

The routines have been crafted in obfuscated modular arithmetic, and points are generally kept in randomly chosen projective coordinates. Point addition is complete in these curves, meaning that no special doubling code is required, and all points defined on the curve can be directly added without watching for singulariites. Point multiplication is performed in obfuscated fashion to thwart side channel sniffing.

This time I make no apologies for using my private Useful-Macros collection, but I have provided them to all who need them. Repositories are located at:

https://github.com/dbmcclain/Edwards-Curves

and 

https://github.com/dbmcclain/useful-macros

No restrictions are placed on this code, but if you find it useful, and make interesting changes / additions, please let me know.

… also provided my implementation of CTR-HASH-DRBG which is used for generating random number from the entropy pool using SHA256 from the Ironclad library. A separate thread runs in the background to produce additional entropy extraction as needed. There is a producer / consumer buffer that triggers the background thread when the pool gets below the low-water mark.

- DM
