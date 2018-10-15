/* MD5.H - header file for MD5C.C
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

#ifndef _MD5_H_
#define _MD5_H_

#ifndef DOXYGEN


#ifdef __cplusplus
extern "C" {
#endif

/* modified for oSIP: GCC supports this feature */
#define PROTOTYPES 1

#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

/* POINTER defines a generic pointer type */
	typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
	typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
	typedef unsigned int UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif


/**
 * Structure for holding MD5 context.
 * @var MD5_CTX
 */
	typedef struct {
		UINT4 state[4];			/* state (ABCD) */
		UINT4 count[2];			/* number of bits, modulo 2^64 (lsb first) */
		unsigned char buffer[64];	/* input buffer */
	} osip_MD5_CTX;

	void osip_MD5Init PROTO_LIST((osip_MD5_CTX *));
	void osip_MD5Update
		PROTO_LIST((osip_MD5_CTX *, unsigned char *, unsigned int));
	void osip_MD5Final PROTO_LIST((unsigned char[16], osip_MD5_CTX *));




#define HASHLEN 16
typedef char HASH[HASHLEN];

#define HASHHEXLEN 32
typedef char HASHHEX[HASHHEXLEN + 1];

#define IN
#define OUT



/* Private functions */
void CvtHex1(IN HASH Bin, OUT HASHHEX Hex);


/* calculate H(A1) as per spec */
void DigestCalcHA1(IN const char *pszAlg,
                   IN const char *pszUserName,
                   IN const char *pszRealm,
                   IN const char *pszPassword,
                   IN const char *pszNonce,
                   IN const char *pszCNonce, OUT HASHHEX SessionKey);

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
                        /* request-digest or response-digest */);

void DigestCalcMD5(IN const char *pszIN, OUT HASHHEX MD5);

/*"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";*/

static int base64_val(char x);

char *base64_decode_string(const char *buf, unsigned int len, int *newlen);


char *base64_encode_string(const char *buf, unsigned int len, int *newlen);






#ifdef __cplusplus
}
#endif
#endif
#endif
