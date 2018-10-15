/* This is a modified version from Aymeric MOIZARD
   of MD5C.C provided by RSA Data Security, Inc.
   modification:
   path for include files
*/

/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* modified for oSIP */

#ifndef NO_MD5_SUPPORT

#include <stdio.h>
#include <stdlib.h>
#include <eXosip2/eXosip.h>

#include "osip_md5.h"

/* Constants for MD5Transform routine.
 */


#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void osip_MD5Transform PROTO_LIST((UINT4[4], unsigned char[64]));
static void osip_Encode PROTO_LIST((unsigned char *, UINT4 *, unsigned int));
static void osip_Decode PROTO_LIST((UINT4 *, unsigned char *, unsigned int));
static void osip_MD5_memcpy PROTO_LIST((POINTER, POINTER, unsigned int));
static void osip_MD5_memset PROTO_LIST((POINTER, int, unsigned int));

static unsigned char PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
void osip_MD5Init(osip_MD5_CTX * context	/* context */
	)
{
	context->count[0] = context->count[1] = 0;
	/* Load magic initialization constants.
	 */
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
void osip_MD5Update(osip_MD5_CTX * context,	/* context */
					unsigned char *input,	/* input block */
					unsigned int inputLen	/* length of input block */
	)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int) ((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((UINT4) inputLen << 3)) < ((UINT4) inputLen << 3))
		context->count[1]++;
	context->count[1] += ((UINT4) inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible.
	 */
	if (inputLen >= partLen) {
		osip_MD5_memcpy((POINTER) & context->buffer[index], (POINTER) input,
						partLen);
		osip_MD5Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			osip_MD5Transform(context->state, &input[i]);

		index = 0;
	} else
		i = 0;

	/* Buffer remaining input */
	osip_MD5_memcpy
		((POINTER) & context->buffer[index], (POINTER) & input[i], inputLen - i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void osip_MD5Final(unsigned char digest[16],	/* message digest */
				   osip_MD5_CTX * context	/* context */
	)
{
	unsigned char bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	osip_Encode(bits, context->count, 8);

	/* Pad out to 56 mod 64.
	 */
	index = (unsigned int) ((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	osip_MD5Update(context, PADDING, padLen);

	/* Append length (before padding) */
	osip_MD5Update(context, bits, 8);

	/* Store state in digest */
	osip_Encode(digest, context->state, 16);

	/* Zeroize sensitive information.
	 */
	osip_MD5_memset((POINTER) context, 0, sizeof(*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void osip_MD5Transform(UINT4 state[4], unsigned char block[64])
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	osip_Decode(x, block, 64);

	/* Round 1 */
	FF(a, b, c, d, x[0], S11, 0xd76aa478);	/* 1 */
	FF(d, a, b, c, x[1], S12, 0xe8c7b756);	/* 2 */
	FF(c, d, a, b, x[2], S13, 0x242070db);	/* 3 */
	FF(b, c, d, a, x[3], S14, 0xc1bdceee);	/* 4 */
	FF(a, b, c, d, x[4], S11, 0xf57c0faf);	/* 5 */
	FF(d, a, b, c, x[5], S12, 0x4787c62a);	/* 6 */
	FF(c, d, a, b, x[6], S13, 0xa8304613);	/* 7 */
	FF(b, c, d, a, x[7], S14, 0xfd469501);	/* 8 */
	FF(a, b, c, d, x[8], S11, 0x698098d8);	/* 9 */
	FF(d, a, b, c, x[9], S12, 0x8b44f7af);	/* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1);	/* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be);	/* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122);	/* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193);	/* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e);	/* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821);	/* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[1], S21, 0xf61e2562);	/* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340);	/* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51);	/* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);	/* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d);	/* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453);	/* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681);	/* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);	/* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6);	/* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6);	/* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87);	/* 27 */
	GG(b, c, d, a, x[8], S24, 0x455a14ed);	/* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905);	/* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8);	/* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9);	/* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);	/* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[5], S31, 0xfffa3942);	/* 33 */
	HH(d, a, b, c, x[8], S32, 0x8771f681);	/* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122);	/* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c);	/* 36 */
	HH(a, b, c, d, x[1], S31, 0xa4beea44);	/* 37 */
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9);	/* 38 */
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60);	/* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70);	/* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6);	/* 41 */
	HH(d, a, b, c, x[0], S32, 0xeaa127fa);	/* 42 */
	HH(c, d, a, b, x[3], S33, 0xd4ef3085);	/* 43 */
	HH(b, c, d, a, x[6], S34, 0x4881d05);	/* 44 */
	HH(a, b, c, d, x[9], S31, 0xd9d4d039);	/* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5);	/* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8);	/* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665);	/* 48 */

	/* Round 4 */
	II(a, b, c, d, x[0], S41, 0xf4292244);	/* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97);	/* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7);	/* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039);	/* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3);	/* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92);	/* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d);	/* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1);	/* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f);	/* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0);	/* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314);	/* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1);	/* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82);	/* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235);	/* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb);	/* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391);	/* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information.
	 */
	osip_MD5_memset((POINTER) x, 0, sizeof(x));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void osip_Encode(unsigned char *output, UINT4 * input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char) (input[i] & 0xff);
		output[j + 1] = (unsigned char) ((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char) ((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char) ((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
  a multiple of 4.
 */
static void osip_Decode(UINT4 * output, unsigned char *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((UINT4) input[j]) | (((UINT4) input[j + 1]) << 8) |
			(((UINT4) input[j + 2]) << 16) | (((UINT4) input[j + 3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */

static void osip_MD5_memcpy(POINTER output, POINTER input, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
static void osip_MD5_memset(POINTER output, int value, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		((char *) output)[i] = (char) value;
}



void CvtHex1(IN HASH Bin, OUT HASHHEX Hex)
{
	unsigned short i;
	unsigned char j;

	for (i = 0; i < HASHLEN; i++)
	{
		j = (Bin[i] >> 4) & 0xf;
		if (j <= 9)
		{
			Hex[i * 2] = (j + '0');
		}
		else
		{
			Hex[i * 2] = (j + 'a' - 10);
		}
		j = Bin[i] & 0xf;
		if (j <= 9)
		{
			Hex[i * 2 + 1] = (j + '0');
		}
		else
		{
			Hex[i * 2 + 1] = (j + 'a' - 10);
		}
	};
	Hex[HASHHEXLEN] = '\0';
}

/* calculate H(A1) as per spec */
void DigestCalcHA1(IN const char *pszAlg,
                   IN const char *pszUserName,
                   IN const char *pszRealm,
                   IN const char *pszPassword,
                   IN const char *pszNonce,
                   IN const char *pszCNonce, OUT HASHHEX SessionKey)
{
	osip_MD5_CTX Md5Ctx;
	HASH HA1;

	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszUserName, strlen(pszUserName));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszRealm, strlen(pszRealm));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszPassword, strlen(pszPassword));
	osip_MD5Final((unsigned char *) HA1, &Md5Ctx);
	if ((pszAlg != NULL) && osip_strcasecmp(pszAlg, "md5-sess") == 0)
	{
		osip_MD5Init(&Md5Ctx);
		osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHLEN);
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszCNonce, strlen(pszCNonce));
		osip_MD5Final((unsigned char *) HA1, &Md5Ctx);
	}
	CvtHex1(HA1, SessionKey);
}

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(IN HASHHEX HA1,	/* H(A1) */
                        IN const char *pszNonce,	/* nonce from server */
                        IN const char *pszNonceCount,	/* 8 hex digits */
                        IN const char *pszCNonce,	/* client nonce */
                        IN const char *pszQop,	/* qop-value: "", "auth", "auth-int" */
                        IN int Aka,	/* Calculating AKAv1-MD5 response */
                        IN const char *pszMethod,	/* method from the request */
                        IN const char *pszDigestUri,	/* requested URL */
                        IN HASHHEX HEntity,	/* H(entity body) if qop="auth-int" */
                        OUT HASHHEX Response
                        /* request-digest or response-digest */)
{
	osip_MD5_CTX Md5Ctx;
	HASH HA2;
	HASH RespHash;
	HASHHEX HA2Hex;

	/* calculate H(A2) */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszMethod, strlen(pszMethod));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszDigestUri, strlen(pszDigestUri));

	if (pszQop == NULL)
	{
		goto auth_withoutqop;
	}
	else if (0 == osip_strcasecmp(pszQop, "auth-int"))
	{
		goto auth_withauth_int;
	}
	else if (0 == osip_strcasecmp(pszQop, "auth"))
	{
		goto auth_withauth;
	}

auth_withoutqop:
	osip_MD5Final((unsigned char *) HA2, &Md5Ctx);
	CvtHex1(HA2, HA2Hex);

	/* calculate response */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHHEXLEN);
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);

	goto end;

auth_withauth_int:

	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HEntity, HASHHEXLEN);

auth_withauth:
	osip_MD5Final((unsigned char *) HA2, &Md5Ctx);
	CvtHex1(HA2, HA2Hex);

	/* calculate response */
	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) HA1, HASHHEXLEN);
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonce, strlen(pszNonce));
	osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	if (Aka == 0)
	{
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszNonceCount,
		               strlen(pszNonceCount));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszCNonce, strlen(pszCNonce));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
		osip_MD5Update(&Md5Ctx, (unsigned char *) pszQop, strlen(pszQop));
		osip_MD5Update(&Md5Ctx, (unsigned char *) ":", 1);
	}
end:
	osip_MD5Update(&Md5Ctx, (unsigned char *) HA2Hex, HASHHEXLEN);
	osip_MD5Final((unsigned char *) RespHash, &Md5Ctx);
	CvtHex1(RespHash, Response);
}

void DigestCalcMD5(IN const char *pszIN, OUT HASHHEX MD5)
{
	osip_MD5_CTX Md5Ctx;
	HASH HA1;

	osip_MD5Init(&Md5Ctx);
	osip_MD5Update(&Md5Ctx, (unsigned char *) pszIN, strlen(pszIN));
	osip_MD5Final((unsigned char *) HA1, &Md5Ctx);
	CvtHex1(HA1, MD5);
}

/*"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";*/

static int base64_val(char x)
{
	switch (x)
	{
	case '=':
		return -1;
	case 'A':
		return OSIP_SUCCESS;
	case 'B':
		return 1;
	case 'C':
		return 2;
	case 'D':
		return 3;
	case 'E':
		return 4;
	case 'F':
		return 5;
	case 'G':
		return 6;
	case 'H':
		return 7;
	case 'I':
		return 8;
	case 'J':
		return 9;
	case 'K':
		return 10;
	case 'L':
		return 11;
	case 'M':
		return 12;
	case 'N':
		return 13;
	case 'O':
		return 14;
	case 'P':
		return 15;
	case 'Q':
		return 16;
	case 'R':
		return 17;
	case 'S':
		return 18;
	case 'T':
		return 19;
	case 'U':
		return 20;
	case 'V':
		return 21;
	case 'W':
		return 22;
	case 'X':
		return 23;
	case 'Y':
		return 24;
	case 'Z':
		return 25;
	case 'a':
		return 26;
	case 'b':
		return 27;
	case 'c':
		return 28;
	case 'd':
		return 29;
	case 'e':
		return 30;
	case 'f':
		return 31;
	case 'g':
		return 32;
	case 'h':
		return 33;
	case 'i':
		return 34;
	case 'j':
		return 35;
	case 'k':
		return 36;
	case 'l':
		return 37;
	case 'm':
		return 38;
	case 'n':
		return 39;
	case 'o':
		return 40;
	case 'p':
		return 41;
	case 'q':
		return 42;
	case 'r':
		return 43;
	case 's':
		return 44;
	case 't':
		return 45;
	case 'u':
		return 46;
	case 'v':
		return 47;
	case 'w':
		return 48;
	case 'x':
		return 49;
	case 'y':
		return 50;
	case 'z':
		return 51;
	case '0':
		return 52;
	case '1':
		return 53;
	case '2':
		return 54;
	case '3':
		return 55;
	case '4':
		return 56;
	case '5':
		return 57;
	case '6':
		return 58;
	case '7':
		return 59;
	case '8':
		return 60;
	case '9':
		return 61;
	case '+':
		return 62;
	case '/':
		return 63;
	}
	return OSIP_SUCCESS;
}


char *base64_decode_string(const char *buf, unsigned int len, int *newlen)
{
	unsigned int i, j;
	int x1, x2, x3, x4;
	char *out;
	out = (char *) osip_malloc((len * 3 / 4) + 8);
	if (out == NULL)
	{
		return NULL;
	}
	for (i = 0, j = 0; i + 3 < len; i += 4)
	{
		x1 = base64_val(buf[i]);
		x2 = base64_val(buf[i + 1]);
		x3 = base64_val(buf[i + 2]);
		x4 = base64_val(buf[i + 3]);
		out[j++] = (x1 << 2) | ((x2 & 0x30) >> 4);
		out[j++] = ((x2 & 0x0F) << 4) | ((x3 & 0x3C) >> 2);
		out[j++] = ((x3 & 0x03) << 6) | (x4 & 0x3F);
	}
	if (i < len)
	{
		x1 = base64_val(buf[i]);
		if (i + 1 < len)
		{
			x2 = base64_val(buf[i + 1]);
		}
		else
		{
			x2 = -1;
		}
		if (i + 2 < len)
		{
			x3 = base64_val(buf[i + 2]);
		}
		else
		{
			x3 = -1;
		}
		if (i + 3 < len)
		{
			x4 = base64_val(buf[i + 3]);
		}
		else
		{
			x4 = -1;
		}
		if (x2 != -1)
		{
			out[j++] = (x1 << 2) | ((x2 & 0x30) >> 4);
			if (x3 == -1)
			{
				out[j++] = ((x2 & 0x0F) << 4) | ((x3 & 0x3C) >> 2);
				if (x4 == -1)
				{
					out[j++] = ((x3 & 0x03) << 6) | (x4 & 0x3F);
				}
			}
		}
	}

	out[j++] = 0;
	*newlen = j;
	return out;
}

char base64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode_string(const char *buf, unsigned int len, int *newlen)
{
	int i, k;
	int triplets, rest;
	char *out, *ptr;

	triplets = len / 3;
	rest = len % 3;
	out = (char *) osip_malloc((triplets * 4) + 8);
	if (out == NULL)
	{
		return NULL;
	}

	ptr = out;
	for (i = 0; i < triplets * 3; i += 3)
	{
		k = (((unsigned char) buf[i]) & 0xFC) >> 2;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i]) & 0x03) << 4;
		k |= (((unsigned char) buf[i + 1]) & 0xF0) >> 4;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i + 1]) & 0x0F) << 2;
		k |= (((unsigned char) buf[i + 2]) & 0xC0) >> 6;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i + 2]) & 0x3F);
		*ptr = base64[k];
		ptr++;
	}
	i = triplets * 3;
	switch (rest)
	{
	case 0:
		break;
	case 1:
		k = (((unsigned char) buf[i]) & 0xFC) >> 2;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i]) & 0x03) << 4;
		*ptr = base64[k];
		ptr++;

		*ptr = '=';
		ptr++;

		*ptr = '=';
		ptr++;
		break;
	case 2:
		k = (((unsigned char) buf[i]) & 0xFC) >> 2;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i]) & 0x03) << 4;
		k |= (((unsigned char) buf[i + 1]) & 0xF0) >> 4;
		*ptr = base64[k];
		ptr++;

		k = (((unsigned char) buf[i + 1]) & 0x0F) << 2;
		*ptr = base64[k];
		ptr++;

		*ptr = '=';
		ptr++;
		break;
	}

	*newlen = ptr - out;
	return out;
}







#endif
