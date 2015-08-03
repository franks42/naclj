/**
 * Copyright 2015 Frank Siebenlist
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * This file is based on Kalium's org.abstractj.kalium/NaCl.java
 * (Thanks Bruno!!!)
 * but is heavily extended with more interface definitions
 * and tries to substitute the defined constants with equivalent libsodium calls
 * for use with the naclj library
 */


package com.github.franks42.naclj;

import jnr.ffi.LibraryLoader;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.LongLongByReference;
import jnr.ffi.types.u_int64_t;

public class NaCl {

    public static Sodium sodium() {
        Sodium sodium = SingletonHolder.SODIUM_INSTANCE;

        if(!(sodium.sodium_version_string().compareTo("0.4.0") >= 0)){
            String message = String.format("Unsupported libsodium version: %s. Please update",
                    sodium.sodium_version_string());
            throw new UnsupportedOperationException(message);
        }
        return sodium;
    }

    private static final String LIBRARY_NAME = "sodium";

    private static final class SingletonHolder {
        public static final Sodium SODIUM_INSTANCE = LibraryLoader.create(Sodium.class)
                .search("/usr/local/lib")
                .search("/opt/local/lib")
                .search("lib")
                .load(LIBRARY_NAME);

    }

    private NaCl() {
    }

    public interface Sodium {

        /**
         * This function isn't thread safe. Be sure to call it once, and before performing other operations.
         *
         * Check libsodium's documentation for more info.
         */
        public int sodium_init();

        public String sodium_version_string();

// box_curve25519xsalsa20poly1305_api.c
        public int crypto_box_curve25519xsalsa20poly1305_seedbytes();
        public int crypto_box_curve25519xsalsa20poly1305_publickeybytes();
        public int crypto_box_curve25519xsalsa20poly1305_secretkeybytes();
        public int crypto_box_curve25519xsalsa20poly1305_beforenmbytes();
        public int crypto_box_curve25519xsalsa20poly1305_noncebytes();
        public int crypto_box_curve25519xsalsa20poly1305_zerobytes();
        public int crypto_box_curve25519xsalsa20poly1305_boxzerobytes();
        public int crypto_box_curve25519xsalsa20poly1305_macbytes();
// auth_sha256_api.c
        public int crypto_hash_sha256_bytes();
        public int crypto_hash_sha256_statebytes();
// auth_sha512_api.c
        public int crypto_hash_sha512_bytes();
        public int crypto_hash_sha512_statebytes();
// auth_hmacsha256_api.c
        public int crypto_auth_hmacsha256_bytes();
        public int crypto_auth_hmacsha256_keybytes();
        public int crypto_auth_hmacsha256_statebytes();
// auth_hmacsha512_api.c
        public int crypto_auth_hmacsha512_bytes();
        public int crypto_auth_hmacsha512_keybytes();
        public int crypto_auth_hmacsha512_statebytes();
// crypto_generichash.c
        public int crypto_generichash_bytes_min();
        public int crypto_generichash_bytes_max();
        public int crypto_generichash_bytes();
        public int crypto_generichash_keybytes_min();
        public int crypto_generichash_keybytes_max();
        public int crypto_generichash_keybytes();
        public int crypto_generichash_statebytes();
// crypto_generichash_blake2_api.c
        public int crypto_generichash_blake2b_bytes_min();
        public int crypto_generichash_blake2b_bytes_max();
        public int crypto_generichash_blake2b_bytes();
        public int crypto_generichash_blake2b_keybytes_min();
        public int crypto_generichash_blake2b_keybytes_max();
        public int crypto_generichash_blake2b_keybytes();
        public int crypto_generichash_blake2b_saltbytes();
        public int crypto_generichash_blake2b_personalbytes();

// crypto_sign_ed25519.h

        public int crypto_sign_ed25519_bytes();
        public int crypto_sign_ed25519_seedbytes();
        public int crypto_sign_ed25519_publickeybytes();
        public int crypto_sign_ed25519_secretkeybytes();

// 


// HMACSHA512256

        public static final int HMACSHA512256_BYTES = 32;

        public static final int HMACSHA512256_KEYBYTES = 32;

        public int crypto_auth_hmacsha512256(@Out byte[] mac, @In byte[] message, @u_int64_t long sizeof, @In byte[] key);

        public int crypto_auth_hmacsha512256_verify(@In byte[] mac, @In byte[] message, @u_int64_t long sizeof, @In byte[] key);

// SHA256

        public static final int SHA256BYTES = 32;

        public int crypto_hash_sha256(@Out byte[] buffer, @In byte[] message, @u_int64_t long sizeof);
        
        public int crypto_hash_sha256_init(@Out byte[] state); 
        public int crypto_hash_sha256_update(byte[] state, @In byte[] in, @u_int64_t long inlen);
        public int crypto_hash_sha256_final(byte[] state, @Out byte[] out);


// SHA512

        public static final int SHA512BYTES = 64;

        public int crypto_hash_sha512(@Out byte[] buffer, @In byte[] message, @u_int64_t long sizeof);

        public int crypto_hash_sha512_init(@Out byte[] state); 
        public int crypto_hash_sha512_update(byte[] state, @In byte[] in, @u_int64_t long inlen);
        public int crypto_hash_sha512_final(byte[] state, @Out byte[] out);

// BLAKE2B

        public static final int BLAKE2B_OUTBYTES = 64;
        public int crypto_generichash_blake2b(@Out byte[] buffer, @u_int64_t long outLen,
                                              @In byte[] message, @u_int64_t long messageLen,
                                              @In byte[] key, @u_int64_t long keyLen);
        public int crypto_generichash_blake2b_salt_personal(@Out byte[] buffer, @u_int64_t long outLen,
                                                            @In byte[] message, @u_int64_t long messageLen,
                                                            @In byte[] key,  @u_int64_t long keyLen,
                                                            @In byte[] salt,
                                                            @In byte[] personal);

        public int crypto_generichash_blake2b_init(@Out byte[] state, 
                                                   @In byte[] key, @u_int64_t long keylen, 
                                                   @u_int64_t long outlen);
        public int crypto_generichash_blake2b_init_salt_personal(@Out byte[] state, 
                                                   @In byte[] key, @u_int64_t long keylen, 
                                                   @u_int64_t long outlen,
                                                   @In byte[] salt, @In byte[] personal);
        public int crypto_generichash_blake2b_update(byte[] state,
                                                     @In byte[] in, @u_int64_t long inlen);
        public int crypto_generichash_blake2b_final(byte[] state,
                                                    @Out byte[] out, @u_int64_t long outlen);


// CURVE25519

        public static final int PUBLICKEY_BYTES = 32;
        public static final int SECRETKEY_BYTES = 32;

        public int crypto_box_curve25519xsalsa20poly1305_keypair(@Out byte[] publicKey, @Out byte[] secretKey);

        // int crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
        // public int crypto_scalarmult_base(@Out byte[] publicKey, @In byte[] secretKey);
        public int crypto_scalarmult_curve25519_base(@Out byte[] publicKey, @In byte[] secretKey);
        
        // int crypto_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk)
        // int crypto_box_curve25519xsalsa20poly1305_beforenm(
        //            unsigned char *k, const unsigned char *pk, const unsigned char *sk);
        public int crypto_box_beforenm(@Out byte[] k, @In byte[] publicKey, @In byte[] secretKey);
        public int crypto_box_curve25519xsalsa20poly1305_beforenm(@Out byte[] k, @In byte[] publicKey, @In byte[] secretKey);

// crypto_box
        
        public static final int NONCE_BYTES = 24;
        public static final int ZERO_BYTES = 32;
        public static final int BOXZERO_BYTES = 16;

        public void randombytes(@Out byte[] buffer, @u_int64_t long size);

        public int crypto_box_curve25519xsalsa20poly1305(@Out byte[] ct, @In byte[] msg, @u_int64_t long length, @In byte[] nonce,
                                                         @In byte[] publicKey, @In byte[] privateKey);

        public int crypto_box_curve25519xsalsa20poly1305_open(@Out byte[] message, @In byte[] ct, @u_int64_t long length,
                                                              @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

// crypto_secretbox

        public static final int SCALAR_BYTES = 32;

        public int crypto_scalarmult_curve25519(@Out byte[] result, @In byte[] intValue, @In byte[] point);

        public static final int XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32;
        public static final int XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24;

        int crypto_secretbox_xsalsa20poly1305(@Out byte[] ct, 
                                              @In byte[] msg, @u_int64_t long length, 
                                              @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_xsalsa20poly1305_open(@Out byte[] message, 
                                                   @In byte[] ct, @u_int64_t long length, 
                                                   @In byte[] nonce, @In byte[] key);

// crypto_ed25519

        int crypto_sign_ed25519_seed_keypair(@Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        int crypto_sign_ed25519_keypair(@Out byte[] publicKey, @Out byte[] secretKey);


        int crypto_sign_ed25519_pk_to_curve25519(@Out byte[] curve25519_pk,
                                                 @In byte[] ed25519_pk);

        int crypto_sign_ed25519_sk_to_curve25519(@Out byte[] curve25519_sk,
                                                 @In byte[] ed25519_sk);

        int crypto_sign_ed25519_sk_to_seed(@Out byte[] seed, @In byte[] sk);

        int crypto_sign_ed25519_sk_to_pk(@Out byte[] pk, @In byte[] sk);



// crypto_sign

        int crypto_sign_ed25519(@Out byte[] buffer, @Out LongLongByReference bufferLen, 
                                @In byte[] message, @u_int64_t long length, 
                                @In byte[] secretKey);

        int crypto_sign_ed25519_open(@Out byte[] buffer, @Out LongLongByReference bufferLen, 
                                     @In byte[] sigAndMsg, @u_int64_t long length, 
                                     @In byte[] key);

        int crypto_sign_ed25519_detached(@Out byte[] sig,
                                         @Out LongLongByReference siglen_p,
                                         @In byte[] m,
                                         @u_int64_t long mlen,
                                         @In byte[] sk);

        int crypto_sign_ed25519_verify_detached(@In byte[] sig,
                                                @In byte[] m,
                                                @u_int64_t long mlen,
                                                @In byte[] pk);




    }

    /**
     * This function isn't thread safe. Be sure to call it once, and before performing other operations.
     *
     * Check libsodium's <i>sodium_init()</i> documentation for more info.
     */
    public static int init() {
        return sodium().sodium_init();
    }
}
