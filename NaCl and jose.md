# NaCl and JOSE

IETF's JavaScript Object Notation (JSON) provides a well-documented way for NaCl to express symmetric, private and pubic keys, and signed and encrypted messages in json.

## Jose?

???


## Keys

* curve25519 private key

    {"kty":"EC",
     "crv":"curve25519",
     "key_ops": "decrypt"
     "sk":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
     "kid":"urn:nacl:sk:curve25519:KSSPKKWRrSaZ5wL3PCDV1jE-31McqaBMq6Tbn_BQoCw"
    }

* curve25519 public key

    {"kty": "EC",
     "crv": "curve25519",
     "key_ops": "encrypt"
     "pk":  "KSSPKKWRrSaZ5wL3PCDV1jE-31McqaBMq6Tbn_BQoCw",
     "kid": "urn:nacl:pk:curve25519:KSSPKKWRrSaZ5wL3PCDV1jE-31McqaBMq6Tbn_BQoCw"
    }

* ed25519 private key

    {"kty":"EC",
     "crv":"ed25519",
     "key_ops": "sign"
     "sk":"-hLokXzxF1iZ2pkuhz7SdvqtJxICxyVoBiAQ0hVjmpFXaPKF3y1f7X2-kSHKsPMgeBRjIMDkxLVCLvWLDVJQ_Q",
     "kid":"urn:nacl:sk:ed25519:3D5G6BsTe9GCJz0bm_Z5b_N8NTIpcb7tAeUv4MnBGIU"
    }

* ed25519 public key

    {"kty": "EC",
     "crv": "ed25519",
     "key_ops": "verify"
     "pk":  "3D5G6BsTe9GCJz0bm_Z5b_N8NTIpcb7tAeUv4MnBGIU",
     "kid": "urn:nacl:pk:ed25519:3D5G6BsTe9GCJz0bm_Z5b_N8NTIpcb7tAeUv4MnBGIU"
    }


## References

* IETF's Javascript Object Signing and Encryption (jose) Charter
  * https://datatracker.ietf.org/wg/jose/charter/
* Use Cases and Requirements for JSON Object Signing and Encryption (JOSE)
  * https://datatracker.ietf.org/doc/rfc7165/
* JSON Web Signature (JWS)
  * https://datatracker.ietf.org/doc/rfc7515/
* JSON Web Encryption (JWE)
  * https://datatracker.ietf.org/doc/rfc7516/
* JSON Web Key (JWK)
  * https://datatracker.ietf.org/doc/rfc7517/
* JSON Web Algorithms (JWA)
  * https://datatracker.ietf.org/doc/rfc7518/
* Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
  * https://datatracker.ietf.org/doc/rfc7520/
        
