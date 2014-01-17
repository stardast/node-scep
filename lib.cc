#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

extern void init_lib(void) asm("_init_lib");
extern int Verify_Response(unsigned char* p7_buf, size_t p7_len, unsigned char* crt_buf, size_t crt_len, unsigned char* in_buf, size_t in_len, char **data, size_t &length ) asm("_verify");
extern int Extract_CSR(unsigned char* p7_buf, size_t p7_len, char *cert, char *key,  char **data, size_t &length) asm("_extract_csr");
extern int Encode_Res(unsigned char* crt_buf, size_t crt_len, unsigned char* p7_buf, size_t p7_len, char *cert, char *key,  char **data, size_t &length) asm("_encode_res");

int Extract_CSR(unsigned char* p7_buf, size_t p7_len, char *cert, char *key,  char **data, size_t &length) {

    BIO *in = BIO_new_mem_buf(p7_buf, p7_len);
    if (!in) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    PKCS7 *p7sign = d2i_PKCS7_bio(in, NULL);
    if (!p7sign) {
        ERR_print_errors_fp(stderr);
        BIO_free(in);
        return 0;
    }
    BIO* out_verify = BIO_new(BIO_s_mem());
    X509_STORE *store = X509_STORE_new();

    int p7vercode = PKCS7_verify(p7sign, NULL, store, /*STACK_OF(X509) *certs,*/ NULL, out_verify, PKCS7_NOVERIFY | PKCS7_NOCHAIN | PKCS7_NOSIGS);
    if(p7vercode!=1){
        fprintf (stderr, "PKCS7_verify ERROR: %lu %d\n", ERR_get_error(), p7vercode );
        BIO_free(in);
        PKCS7_free(p7sign);
        BIO_free(out_verify);
        X509_STORE_free(store);
        return 0;
    }

    FILE *fp;
    X509 *ca_cert = NULL;
    /* read the signer certificate */
    if (!(fp = fopen (cert, "r")) || !(ca_cert = PEM_read_X509 (fp, NULL, NULL, NULL))) {
        fprintf (stderr, "Error reading signer certificate in %s\n", cert);
        BIO_free(in);
        PKCS7_free(p7sign);
        BIO_free(out_verify);
        X509_STORE_free(store);
        fclose (fp);
        return 0;
    }
    fclose (fp);

    EVP_PKEY *cakey = NULL;
    /* read the signer private key */
    if (!(fp = fopen (key, "r")) || !(cakey = PEM_read_PrivateKey (fp, NULL, NULL, NULL))) {
        fprintf (stderr, "Error reading signer private key in %s\n", key );
        BIO_free(in);
        PKCS7_free(p7sign);
        BIO_free(out_verify);
        X509_STORE_free(store);
        fclose (fp);
        X509_free(ca_cert);
        return 0;
    }
    fclose (fp);

    PKCS7 *p7enc = d2i_PKCS7_bio(out_verify, NULL);

    BIO* csr_bio = BIO_new(BIO_s_mem());
    if(PKCS7_decrypt(p7enc, cakey, ca_cert, csr_bio, 0) == 0){
	fprintf (stderr, "PKCS7_decrypt ERROR: %lu\n", ERR_get_error() );
        BIO_free(in);
        PKCS7_free(p7sign);
        BIO_free(out_verify);
        X509_STORE_free(store);
        X509_free(ca_cert);
        EVP_PKEY_free(cakey);
        PKCS7_free(p7enc);
        BIO_free(csr_bio);
        return 0;
    }

    X509_REQ *csr = d2i_X509_REQ_bio(csr_bio, NULL);
    BIO* csr_pem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(csr_pem, csr);

    BUF_MEM *bptr_csr;
    BIO_get_mem_ptr(csr_pem, &bptr_csr);

    *data = bptr_csr->data;
    length = bptr_csr->length;

    BIO_free(in);
    PKCS7_free(p7sign);
    BIO_free(out_verify);
    X509_STORE_free(store);
    X509_free(ca_cert);
    EVP_PKEY_free(cakey);
    PKCS7_free(p7enc);
    BIO_free(csr_bio);
    X509_REQ_free(csr);

    return 1;
}

int Encode_Res(unsigned char* crt_buf, size_t crt_len, unsigned char* p7_buf, size_t p7_len, char *cert_fn, char *key_fn,  char **data, size_t &length) {

    BIO *crt_bio = BIO_new_mem_buf(crt_buf, crt_len);
    if (!crt_bio) {
        ERR_print_errors_fp(stderr);
	return 0;
    }
    X509 *x509in = d2i_X509_bio(crt_bio, NULL);
    if (!x509in) {
        ERR_print_errors_fp(stderr);
        BIO_free(crt_bio);
	return 0;
    }

    BIO *pkcs7_bio = BIO_new_mem_buf(p7_buf, p7_len);
    if (!pkcs7_bio) {
        ERR_print_errors_fp(stderr);
        BIO_free(crt_bio);
        X509_free(x509in);
	return 0;
    }
    PKCS7 *p7sign = d2i_PKCS7_bio(pkcs7_bio, NULL);
    if (!p7sign) {
        ERR_print_errors_fp(stderr);
        BIO_free(crt_bio);
        X509_free(x509in);
        BIO_free(pkcs7_bio);
	return 0;
    }


    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    STACK_OF (X509) * chain = sk_X509_new_null();
    FILE *fp;
    /* read the signer certificate */
    if (!(fp = fopen (cert_fn, "r")) || !(cert = PEM_read_X509 (fp, NULL, NULL, NULL))) {
        fprintf (stderr, "Error reading signer certificate in %s\n", cert_fn);
        BIO_free(crt_bio);
        X509_free(x509in);
        BIO_free(pkcs7_bio);
        fclose (fp);
        return 0;
    }
    fclose (fp);

    /* read the signer private key */
    if (!(fp = fopen (key_fn, "r")) || !(pkey = PEM_read_PrivateKey (fp, NULL, NULL, NULL))) {
        fprintf (stderr, "Error reading signer private key in %s\n", key_fn );
        BIO_free(crt_bio);
        X509_free(x509in);
        BIO_free(pkcs7_bio);
        fclose (fp);
        X509_free(cert);
        return 0;
    }
    fclose (fp);

    PKCS7 *degenerate_pkcs7 = PKCS7_new();
    PKCS7_set_type(degenerate_pkcs7, NID_pkcs7_signed);
    PKCS7_add_certificate(degenerate_pkcs7, x509in);
    BIO* degenerate_pkcs7_der = BIO_new(BIO_s_mem());
    if(i2d_PKCS7_bio(degenerate_pkcs7_der, degenerate_pkcs7)<=0)
    {
        fprintf (stderr, "ERROR: i2d_PKCS7_bio\n" );
        BIO_free(crt_bio);
        X509_free(x509in);
        BIO_free(pkcs7_bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        PKCS7_free(degenerate_pkcs7);
        BIO_free(degenerate_pkcs7_der);
        return 0;
    }

    STACK_OF(X509) *sk = PKCS7_get0_signers(p7sign, NULL, 0);
    PKCS7 *enc_cert = PKCS7_encrypt(sk, degenerate_pkcs7_der, EVP_des_ede3_cbc(), PKCS7_BINARY);
    if(!enc_cert){
        fprintf (stderr, "ERROR: PKCS7_encrypt\n" );
        BIO_free(crt_bio);
        X509_free(x509in);
        BIO_free(pkcs7_bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        PKCS7_free(degenerate_pkcs7);
        BIO_free(degenerate_pkcs7_der);
        return 0;
    }
    BIO* enc_cert_der = BIO_new(BIO_s_mem());
    if(i2d_PKCS7_bio(enc_cert_der, enc_cert)<=0)
    {
        fprintf (stderr, "ERROR: i2d_PKCS7_bio\n" );
        BIO_free(crt_bio);
        X509_free(x509in);
        BIO_free(pkcs7_bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        PKCS7_free(degenerate_pkcs7);
        BIO_free(degenerate_pkcs7_der);
        PKCS7_free(enc_cert);
        BIO_free(enc_cert_der);
        return 0;
    }

    PKCS7 *reply = PKCS7_sign (cert, pkey, chain, enc_cert_der, PKCS7_BINARY);
    if (!reply) {
        fprintf (stderr, "ERROR: PKCS7_sign\n" );
        BIO_free(crt_bio);
        X509_free(x509in);
        BIO_free(pkcs7_bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        PKCS7_free(degenerate_pkcs7);
        BIO_free(degenerate_pkcs7_der);
        PKCS7_free(enc_cert);
        BIO_free(enc_cert_der);
        return 0;
    }

    BIO* out = BIO_new(BIO_s_mem());
    if(i2d_PKCS7_bio(out, reply)<=0)
    {
        fprintf (stderr, "ERROR: i2d_PKCS7_bio %lu\n", ERR_get_error() );
        BIO_free(crt_bio);
        X509_free(x509in);
        BIO_free(pkcs7_bio);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        PKCS7_free(degenerate_pkcs7);
        BIO_free(degenerate_pkcs7_der);
        PKCS7_free(enc_cert);
        BIO_free(enc_cert_der);
        BIO_free(out);
        return 0;
    }
    BUF_MEM *bptr;
    BIO_get_mem_ptr(out, &bptr);
 
    *data = bptr->data;
    length = bptr->length;

    BIO_free(crt_bio);
    X509_free(x509in);
    BIO_free(pkcs7_bio);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    PKCS7_free(degenerate_pkcs7);
    BIO_free(degenerate_pkcs7_der);
    PKCS7_free(enc_cert);
    BIO_free(enc_cert_der);

    return 1;
}


int Verify_Response(unsigned char* p7_buf, size_t p7_len, unsigned char* crt_buf, size_t crt_len, unsigned char* in_buf, size_t in_len, char **data, size_t &length ) {

    BIO *in = NULL;
    if(in_buf && in_len) in = BIO_new_mem_buf(in_buf, in_len);

    X509 *x509in = NULL;
    if(crt_buf && crt_len) { 
       BIO *crt_bio = BIO_new_mem_buf(crt_buf, crt_len);
       if (!crt_bio) {
           ERR_print_errors_fp(stderr);
           BIO_free(in);
           return 0;
       }
       x509in = PEM_read_bio_X509(crt_bio, NULL, 0, NULL);
       if (!x509in) {
           ERR_print_errors_fp(stderr);
           BIO_free(in);
           BIO_free(crt_bio);
           return 0;
       }
       BIO_free(crt_bio);
    }

    BIO *p7_bio = BIO_new_mem_buf(p7_buf, p7_len);
    if (!p7_bio) {
        ERR_print_errors_fp(stderr);
        BIO_free(in);
        X509_free(x509in);
        return 0;
    }
    PKCS7 *p7sign = d2i_PKCS7_bio(p7_bio, NULL);
    if (!p7sign) {
        ERR_print_errors_fp(stderr);
        BIO_free(in);
        X509_free(x509in);
        BIO_free(p7_bio);
        return 0;
    }
    BIO* out_verify = BIO_new(BIO_s_mem());
    X509_STORE *store = X509_STORE_new();
    int flags = PKCS7_NOVERIFY | PKCS7_NOCHAIN | PKCS7_NOSIGS;
    if(x509in){
       X509_STORE_add_cert(store, x509in);
       flags = 0;
    } 
    STACK_OF (X509) *signers = sk_X509_new_null();

    int p7vercode = PKCS7_verify(p7sign, signers, store, in, out_verify, flags);
    if(p7vercode!=1){
        fprintf (stderr, "PKCS7_verify ERROR: %d\n", p7vercode);
        BIO_free(in);
        X509_free(x509in);
	ERR_print_errors_fp(stderr);
        BIO_free(p7_bio);
        PKCS7_free(p7sign);
        X509_STORE_free(store);
        return 0;
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(out_verify, &bptr);
    *data = bptr->data;
    length = bptr->length;

    BIO_free(in);
    X509_free(x509in);
    BIO_free(p7_bio);
    PKCS7_free(p7sign);
    X509_STORE_free(store);

    return 1;
}


void init_lib() {

//  fprintf (stderr, "Openssl version:%s\n", SSLeay_version(SSLEAY_VERSION));

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();
}

