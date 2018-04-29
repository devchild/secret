#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int base64_encode(unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = (*bufferPtr).data;

    return (*bufferPtr).length; //success
}

size_t calc_base64_decode_length(const char* b64input) { //Calculates the length of a decoded string
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') //last char is =
        padding = 1;

    return (len * 3) / 4 - padding;
}

int base64_decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
    BIO *bio, *b64;

    int decodeLen = calc_base64_decode_length(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
    BIO_free_all(bio);

    return (0); //success
}

void PBKDF2_HMAC_SHA_1nat_string(const char* pass, size_t pwd_len, const unsigned char* salt, size_t sz_salt, int32_t iterations, uint32_t keySize, unsigned char** res)
{
    unsigned char *password = (unsigned char*)malloc(sizeof(unsigned char*)* (keySize + 16 + 1));
    PKCS5_PBKDF2_HMAC_SHA1(pass, pwd_len, salt, sz_salt, iterations, keySize + 16, password);
    //Base64Encode(digest, sizeof(digest), &base64Result);

    char* passwordBytes_base64;
    int s = base64_encode(password, keySize + 16, &passwordBytes_base64);
    passwordBytes_base64[s] = '\0';
    //printf("PBKDF2_HMAC_SHA_1nat_string:%s\n", passwordBytes_base64);
    *res = password;
}

unsigned char* aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *passwordBytes, size_t pwd_len, int *rb)
{
    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    const unsigned char salt[] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
    /* A 256 bit key */
    unsigned char * key = { 0 };
    PBKDF2_HMAC_SHA_1nat_string((const char*)passwordBytes, pwd_len, salt, sizeof(salt), 1000, 32 + 16, &key);

    /* A 128 bit IV */
    unsigned char * iv = &key[32];

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    int  ol, tmp;
    unsigned char *ret;
    ol = 0;
    if (!(ret = (unsigned char *)malloc(plaintext_len + EVP_CIPHER_CTX_block_size(ctx))))
        handleErrors(  );


    if (!EVP_EncryptUpdate(ctx, &ret[ol], &tmp, &plaintext[ol], plaintext_len))
        handleErrors(  );
    ol += tmp;

    if (!EVP_EncryptFinal_ex(ctx, &ret[ol], &tmp))
        handleErrors(  );
    ol += tmp;
    if (rb) *rb = ol;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

unsigned char* aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *passwordBytes, size_t pwd_len, int* rb)
{
    EVP_CIPHER_CTX *ctx;

    const unsigned char salt[] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
    /* A 256 bit key */
    unsigned char * key = { 0 };
    PBKDF2_HMAC_SHA_1nat_string((const char*)passwordBytes, pwd_len, salt, sizeof(salt), 1000, 32 + 16, &key);

    /* A 128 bit IV */
    unsigned char * iv = &key[32];

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
    * and IV size appropriate for your cipher
    * In this example we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    int  ol, tmp;
    unsigned char *pt;

    if (!(pt = (unsigned char *)malloc(ciphertext_len + EVP_CIPHER_CTX_block_size(ctx) + 1)))
        handleErrors(  );

    if (!EVP_DecryptUpdate(ctx, pt, &tmp, ciphertext, ciphertext_len))
        handleErrors();
    ol += tmp;

    if (!EVP_DecryptFinal_ex(ctx, pt + ol, &tmp))
        handleErrors();
    ol += tmp;

    if (!ol) { /* There is no data to decrypt */
        free(pt);
        return 0;
    }
    pt[ol] = 0;
    if (rb) *rb = ol;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return pt;
}

int sha256(const char* str, size_t str_len, unsigned char** out)
{
    unsigned char * hash = (unsigned char*)malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, str_len);
    SHA256_Final(hash, &sha256);
    *out = hash;
    return sha256.md_len;
}

int split(const char* input, char** key, int* key_len, char** value, int* value_len) {
    const char *ptr = strchr(input, '=');
    if (ptr) {
        int index = ptr - input;
        int sz_k = index;
        int sz_v = strlen(input) - 1 - index;

        char* k = (char*)malloc(sizeof(char) * sz_k);
        strncpy(k, input, sz_k);
        k[sz_k] = '\0';
        *key = k;
        *key_len = sz_k;

        if (ptr++)
        {
            char* v = (char*)malloc(sizeof(char) * sz_v);
            strncpy(v, ptr, sz_v);
            v[sz_v] = '\0';
            *value = v;
            *value_len = sz_v;
            return 0;
        }
        else
        {
            *value = "";
            *value_len = 0;
            return 0;
        }
    }
    return -1;
}

enum op_mode { OM_ENCRYPT, OM_DECRYPT };

int process(FILE* fp, char*filename, char* password, enum op_mode mode) {
    size_t sz_password = strlen(password);
    unsigned char* password_bytes;
    size_t sz_password_bytes = sha256(password, sz_password, &password_bytes);

    /* Initialise the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    char *buffer = NULL;
    size_t len;

    while ( getline(&buffer, &len, fp) != -1) /* read a line */
    {
        buffer[strcspn(buffer, "\r\n")] = 0;

        char* key;
        char* value;
        int sz_key, sz_value;
        if (split(buffer, &key, &sz_key, &value, &sz_value) == 0) {
            if (mode == OM_ENCRYPT) {
                unsigned char *ciphertext;
                int ciphertext_len;

                /* Encrypt the plaintext */
                ciphertext = aes_encrypt((unsigned char *) value, sz_value, password_bytes, sz_password_bytes,
                                         &ciphertext_len);

                char *base64encoded;
                int sz = base64_encode(ciphertext, ciphertext_len, &base64encoded);
                base64encoded[sz] = '\0';

                printf("%s=%s\n", key, base64encoded);
            } else {
                unsigned char *ciphertext;
                size_t ciphertext_len;
                base64_decode(value, &ciphertext, &ciphertext_len);

                int decryptedtext_len;
                unsigned char *decryptedtext = aes_decrypt(ciphertext, ciphertext_len, (unsigned char *) password_bytes,
                                                           sz_password_bytes, &decryptedtext_len);
                printf("%s=%s\n", key, decryptedtext);
            }
        }
    }

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}

int main(int argc, char** argv)
{
    // char * password = getCmdOption(argv, argv + argc, "-pwd");
    char * password = "";
    char* fileName = "";
    enum op_mode op_mode = OM_ENCRYPT;
    size_t optind;
    for (optind = 1; optind < argc && argv[optind][0] == '-'; optind++) {
        if (strcmp("-pwd", argv[optind]) == 0) {
            optind++;
            password = argv[optind];
        }
        else if(strcmp("-f", argv[optind]) == 0){
            optind++;
            fileName = argv[optind];
        }
        else if(strcmp("-enc", argv[optind]) == 0){
            op_mode = OM_ENCRYPT;
        }
        else if(strcmp("-dec", argv[optind]) == 0){
            op_mode = OM_DECRYPT;
        }
        else {
            fprintf(stderr, "Usage: %s -pwd [password] [-enc] [-dec] -f [file]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (strlen(fileName) > 0) {
        FILE *fp = fopen(fileName, "r");
        if (fp == 0) {
            fprintf(stderr, "%s: failed to open %s (%d %s)\n", argv[0], fileName, errno, strerror(errno));
        }
        else {
            process(fp, fileName, password, op_mode);
            fclose(fp);
        }
    } else {
        process(stdin, "(standard input)", password, op_mode);
    }

    return 0;
}
