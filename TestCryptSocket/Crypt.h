#ifndef _CRYPTH_
#define _CRYPTH_
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <cstddef>
class Crypt
{
public:
	Crypt();
	~Crypt();
	static char * hashkey(const char *);
	static void randomkey(char tmp[8]);
	static char * desencode(const uint8_t * text,const uint8_t *key);
	static char * desdecode(const uint8_t * text, const uint8_t * key);
	static void hexencode(const uint8_t * text,char * out);
	static char * hexdecode(const char * text);
	static char * hmac64(uint32_t x[2], uint32_t y[2]);
	static void dhexchange(char *x);
	static void dhsecret(char *pubkey, char *prikey, char * secret);
	static void base64encode(const uint8_t *text,char *out);
	static void base64decode(const uint8_t * text,char *out);
};
#endif

