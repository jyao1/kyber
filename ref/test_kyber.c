#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "randombytes.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"
#include "cbd.h"
#include "reduce.h"

#define NTESTS 1000

static int test_keys()
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR keys\n");
    return 1;
  }

  return 0;
}

static int test_invalid_sk_a()
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Replace secret key with random values
  randombytes(sk, CRYPTO_SECRETKEYBYTES);

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid sk\n");
    return 1;
  }

  return 0;
}

static int test_invalid_ciphertext()
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  uint8_t b;
  size_t pos;

  do {
    randombytes(&b, sizeof(uint8_t));
  } while(!b);
  randombytes((uint8_t *)&pos, sizeof(size_t));

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);

  //Change some byte in the ciphertext (i.e., encapsulated key)
  ct[pos % CRYPTO_CIPHERTEXTBYTES] ^= b;

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);

  if(!memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR invalid ciphertext\n");
    return 1;
  }

  return 0;
}

int main1(void)
{
  unsigned int i;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_keys();
    r |= test_invalid_sk_a();
    r |= test_invalid_ciphertext();
    if(r)
      return 1;
  }

  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  return 0;
}

void print_hex_16(char *name, uint8_t *buffer, size_t len)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  }
  for (i = 0; i < len; i++) {
    printf ("%02x, ", buffer[i]);
  }
  printf ("\n");
}

void print_hex(char *name, uint8_t *buffer, size_t len)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  }
  for (i = 0; i < len; i++) {
    printf ("%d, ", buffer[i]);
  }
  printf ("\n");
}

void print_poly(char *name, poly *p)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  } else {
    printf ("<p>: ");
  }
  for (i = 0; i < KYBER_N; i++) {
    printf ("%d, ", p->coeffs[i]);
  }
  printf ("\n");
}

void print_polyvec(char *name, polyvec *pv)
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  } else {
    printf ("<pv>: ");
  }
  for (i = 0; i < KYBER_K; i++) {
    print_poly (NULL, &pv->vec[i]);
  }
  printf ("\n");
}

void print_matrix(char *name, polyvec pv[KYBER_K])
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  }
  for (i = 0; i < KYBER_K; i++) {
    print_polyvec (NULL, &pv[i]);
  }
  printf ("\n");
}

#ifdef KYBER_90S
void print_xof_state (char *name, xof_state *state) // aes256ctr_ctx
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  }
  for (i = 0; i < 120; i++) {
    printf ("%lld, ", state->sk_exp[i]);
  }
  for (i = 0; i < 16; i++) {
    printf ("%d, ", state->ivw[i]);
  }
  printf ("\n");
}
#else
void print_xof_state (char *name, xof_state *state) // keccak_state
{
  size_t i;
  if (name != NULL) {
    printf ("%s: ", name);
  }
  for (i = 0; i < 25; i++) {
    printf ("%llu, ", state->s[i]);
  }
  printf ("%d", state->pos);
  printf ("\n");
}
#endif

static int test_kyber_key_api()
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];

  //Alice generates a public key
  crypto_kem_keypair(pk, sk);
  print_hex ("pk", pk, sizeof(pk));
  print_hex ("sk", sk, sizeof(sk));

  //Bob derives a secret key and creates a response
  crypto_kem_enc(ct, key_b, pk);
  print_hex ("ct", ct, sizeof(ct));
  print_hex ("key_b", key_b, sizeof(key_b));

  //Alice uses Bobs response to get her shared key
  crypto_kem_dec(key_a, ct, sk);
  print_hex ("sk", sk, sizeof(sk));
  print_hex ("key_a", key_a, sizeof(key_a));

  if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR keys\n");
    return 1;
  }

  return 0;
}

void test_cbd ()
{
  poly r;
  uint8_t buf[KYBER_ETA2*KYBER_N/4];

  memset(&r, 0, sizeof(r));
  randombytes(buf, sizeof(buf));

  poly_cbd_eta1 (&r, buf);
//  poly_cbd_eta2 (&r, buf);

  print_hex_16 ("buf", buf, sizeof(buf));
  print_poly ("r", &r);
}

void test_poly_msg ()
{
  poly r;
  uint8_t buf[KYBER_INDCPA_MSGBYTES];

  memset(&r, 0, sizeof(r));
  randombytes(buf, sizeof(buf));

  poly_frommsg (&r, buf);

  print_hex_16 ("msg", buf, sizeof(buf));
  print_poly ("r", &r);
}

void test_poly_decompress ()
{
  poly r;
  uint8_t buf[KYBER_POLYCOMPRESSEDBYTES];

  memset(&r, 0, sizeof(r));
  randombytes(buf, sizeof(buf));

  poly_decompress (&r, buf);

  print_hex_16 ("decompress", buf, sizeof(buf));
  print_poly ("r", &r);
}

void test_montgomery_reduce ()
{
  printf ("redu - 1: %d\n", montgomery_reduce (1));
  printf ("redu - 2: %d\n", montgomery_reduce (2));
  printf ("redu - 3: %d\n", montgomery_reduce (3));
  printf ("redu - -1: %d\n", montgomery_reduce (-1));
  printf ("redu - -2: %d\n", montgomery_reduce (-2));
  printf ("redu - -3: %d\n", montgomery_reduce (-3));
}

void init_ntt();
extern int16_t zetas2[128];
void print_zeta ()
{
  int i;
  printf ("zetas: ");
  for (i = 0; i < 128; i++) {
    printf ("%d ", zetas2[i]);
  }
  printf ("\n");
}

void test_ntt()
{
  poly p;
  unsigned char buf[KYBER_SYMBYTES];

  init_ntt ();
  print_zeta ();

  randombytes(buf, sizeof(buf));
  poly_getnoise_eta1 (&p, buf, 0);
  print_poly ("poly - init", &p);

  poly_ntt (&p);
  print_poly ("poly - ntt", &p);
  poly_invntt_tomont (&p);
  print_poly ("poly - invntt", &p);
}

int main()
{
  //{volatile int ___i=1;while(___i);}
  //test_kyber_key_api();
  //test_poly_decompress();
  //test_montgomery_reduce();
  test_ntt ();

  return 0;
}