#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main() {
    unsigned char c[] =
        "\xdf\xbc\x1f\x3f\x4c\x10\xe1\x7e\x01\x12\xd7\x2e\x78\x91\x6d\xa5\x06\xed\xd5\x7d\xa0\x6e\xac\x6a\xe4\xf0\x0d\xd3\x01\x06\x71\x78\x05\x7b\xaa\x9b\xa9\x4e\xf6\xe6\x65\xbf\xb2\x9c\xee\x56\x7d\xe4\x08\x12\x49\xc0\xbe\x37\x6f\x98\x11\x38\x3c\xe6\xd1\x2b\xad\x74\x4a\x2f\x12\xfc\x16\x18\x9c\x3d\x6e\xc0\x41\x22\x2b\x45\x95\x41\x84\x16\x5f\x37\xd9\x8d\x18\x8e\xd5\xad\x15\x8f\xf8\xb5\x00\x4e\x8e\x71\x7f\x71\x4f\xc9\x62\xab\x7e\xb0\x2d\x58\x48\x19\x60\xd4\xd6\x2f\x09\xc0\xb6\x42\xe4\x96\xec\x70\x3e\xca\x1c"
        "e7K";
    unsigned char *from = (unsigned char *)malloc(100 * sizeof(unsigned char));
    unsigned char a[4] = "\x01\0\x01";
    from = (unsigned char *)malloc(sizeof(unsigned char) * 31);
    time_t now_time = time(NULL);
    strftime((char *)from, 100, "ALSONG_ANDROID_%Y%m%d_%H%M%S", gmtime(&now_time));
    RSA *enc = RSA_new();
    RSA_set0_key(enc, BN_bin2bn(c, 0x80, (BIGNUM *)0x0), BN_bin2bn(a, 3, (BIGNUM *)0x0), (BIGNUM *)0x0);
    RSA_set0_factors(enc, (BIGNUM *)0x0, (BIGNUM *)0x0);
    RSA_set0_crt_params(enc, (BIGNUM *)0x0, (BIGNUM *)0x0, (BIGNUM *)0x0);
    size_t size = RSA_size(enc), flen = strlen((char *)from);
    unsigned char *to = (unsigned char *)malloc(size * sizeof(unsigned char));
    memset(to, 0, size);
    RSA_public_encrypt(flen, from, to, enc, 1);
    for (int i = 0; i < size; i++) {
        printf("%02hX", to[i]);
    }
    free(from);
    RSA_free(enc);
    CRYPTO_cleanup_all_ex_data();
    return 0;
}