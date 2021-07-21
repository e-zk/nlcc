// requires: 
//  - libsodium headers installed
//  - crypto_aead.h, api.h (from NIST competition website)
//  - encrypt.c of cipher you wish to turn into a CLI
// usage: ./nlcc [-m message] [-a associated_data] [-n nonce] [-k keyfile]

#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sodium.h>
#include "crypto_aead.h"
#include "api.h"

// TODO what is the best size for these?
#define MAX_MSG_LEN 256
#define MAX_AD_LEN  256


unsigned char key[CRYPTO_KEYBYTES];
unsigned char nonce[CRYPTO_NPUBBYTES];
unsigned char msg[MAX_MSG_LEN]; // TODO make the same as key?
unsigned char ad[MAX_AD_LEN];   // TODO make same as key?
unsigned char ct[MAX_MSG_LEN + CRYPTO_ABYTES];

unsigned long long mlen, adlen, clen; // sizes
size_t clenz;

// hex digests must be len*2+1
char key_digest[(CRYPTO_KEYBYTES*2)+1];
char nonce_digest[(CRYPTO_NPUBBYTES*2)+1];
char msg_digest[(MAX_MSG_LEN*2)+1];
char ad_digest[(MAX_AD_LEN*2)+1];
char ct_digest[((MAX_MSG_LEN + CRYPTO_ABYTES)*2)+1];

void usage(void);
int init(void);
void cleanup(void);
void init_key(unsigned char *buf, unsigned long long n);

void usage(void)
{
	fprintf(stderr, "nlcc [-h] [-k key_file] [-n nonce_file] [-a associated_data] ");
	fprintf(stderr, "[-m message] [-d ciphertext]\n");
}

int init(void)
{
	// init libsodium
	int ret;
	if ((ret = sodium_init()) < 0) {
		return ret;
	}

	// zero all buffers
	sodium_memzero(key,   sizeof(key));
	sodium_memzero(nonce, sizeof(nonce));
	sodium_memzero(msg,   sizeof(msg));
	sodium_memzero(ad,    sizeof(ad));

	return 0;
}

int main(int argc, char *argv[])
{
	if (init() < 0) {
		errx(1, "aborted. libsodium error.");
	}

	if (argc == 1) {
		usage(); exit(0);
	}

	char c;
	int ret, opt;

	while((opt = getopt(argc, argv, "hk:n:d:a:m:")) != -1) {	
		switch(opt) {
			case 'h':
				usage(); exit(0);
				break; /*NOTREACHED*/
			case 'k':
				if (access(optarg, R_OK) != 0) {
					errx(1, "given key file does not exist.");
				}
				FILE *kf = fopen(optarg, "r");
				if (kf == NULL) {
					errx(1, "error opening key file for reading.");
				}
				for (int i = 0; i <= CRYPTO_KEYBYTES && (unsigned char)c != EOF; i++) {
					c = fgetc(kf);
					key[i] = c;
				}
				fclose(kf);
				break;
			case 'n':
				if (access(optarg, R_OK) != 0) {
					errx(1, "given nonce file does not exist.");
				}
				FILE *nf = fopen(optarg, "r");
				if (nf == NULL) {
					errx(1, "error opening nonce file for reading.");
				}
				for (int i = 0; i <= sizeof(nonce) && (unsigned char)c != EOF; i++) {
					c = fgetc(kf);
					nonce[i] = c;
				}
				fclose(nf);
				break;
			case 'a':
				strncpy(ad, optarg, strlen(optarg));
				adlen = (unsigned long long)strlen(optarg);
				break;
			case 'm':
				// TODO use stdin if given
				strncpy(msg, optarg, strlen(optarg));
				mlen = (unsigned long long)strlen(optarg);
				break;
			case 'd':
				ret = sodium_hex2bin(ct, MAX_MSG_LEN + CRYPTO_ABYTES, optarg, strlen(optarg), NULL, &clenz, NULL);
				clen = (unsigned long long)clenz;
				break;
			case ':':
				fprintf(stderr, "option needs value.\n");
				usage(); exit(1);
				break; /* NOTREACHED */
			case '?':
				fprintf(stderr, "unknown option '%c'.\n", optopt);
				usage(); exit(1);
				break;  /* NOTREACHED */
		}
	}

	// convert to hex for displaying
	sodium_bin2hex(key_digest,   sizeof(key_digest),   key,   sizeof(key));
	sodium_bin2hex(nonce_digest, sizeof(nonce_digest), nonce, sizeof(nonce));
	sodium_bin2hex(ad_digest,    sizeof(ad_digest),    ad,    adlen);

	fprintf(stderr, "Key   = %s (%ld)\n", key_digest,   sizeof(key)*(size_t)8);
	fprintf(stderr, "Nonce = %s (%ld)\n", nonce_digest, sizeof(nonce)*(size_t)8);
	fprintf(stderr, "AD    = %s (%ld)\n", ad_digest,    strlen(ad)*(size_t)8);

	int enc_ret;
	if (clen == 0) {
		// do encryption
		sodium_bin2hex(msg_digest, sizeof(msg_digest), msg, mlen);
		fprintf(stderr, "PT    = %s (\"%s\") (%ld)\n", msg_digest, msg, strlen(msg)*(size_t)8);
		if ((enc_ret = crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key)) != 0) {
			// fail
			errx(1, "encryption operation failed: %d\n", enc_ret);
		}
		sodium_bin2hex(ct_digest, sizeof(ct_digest), ct, clen);
		fprintf(stderr, "CT    = %s\n", ct_digest);
	} else {
		// do decrypt
		sodium_bin2hex(ct_digest, sizeof(ct_digest), ct, clen);
		fprintf(stderr, "CT    = %s (%lld)\n", ct_digest, clen*8);
		if ((enc_ret = crypto_aead_decrypt(msg, &mlen, NULL, ct, clen, ad, adlen, nonce, key)) != 0) {
			// fail
			errx(1, "Decryption operation failed: %d\n", enc_ret);
		}
		sodium_bin2hex(msg_digest, sizeof(msg_digest), msg, mlen);
		fprintf(stderr, "PT    = %s (\"%s\") (%ld)\n", msg_digest, msg, strlen(msg)*(size_t)8);
	}

	cleanup();
	return 0;
}

// generate temp key for testing
void init_key(unsigned char *buf, unsigned long long n) {
	for (unsigned long long i = 0; i < n; i++)
		buf[i] = (unsigned char)i;
}


// zero all buffers.
// only useful for secure usage;
// which is ill advised anyways.
void cleanup(void) {
	sodium_memzero(key,   sizeof(key));
	sodium_memzero(nonce, sizeof(nonce));
	sodium_memzero(msg,   sizeof(msg));
	sodium_memzero(ad,    sizeof(ad));
}
