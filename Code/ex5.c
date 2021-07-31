//NIKOLAOS SERGIS 18390173 PADA EX_5a

#include <stdio.h> //basic library for input/output 
#include <openssl/bn.h> //library that helps the computer to deal with big numbers and not cause overflow
#define NBITS 128 //constant for bn, (in real life problems that number would be at least 512 bits)

//Function that prints a bn number
 void printBN(char *M, BIGNUM * a)
{

 /* Use BN_bn2hex(a) for hex string
 * Use BN_bn2dec(a) for decimal string */
 char * number_str = BN_bn2hex(a);
 printf("%s %s\n", M, number_str);
 OPENSSL_free(number_str);

}

int main ()
{
 BN_CTX *ctx = BN_CTX_new();//a temporary struct to help with the computational process of large numbers
 BIGNUM *S = BN_new(); //bob's
 BIGNUM *d = BN_new(); //private key
 BIGNUM *n = BN_new(); //
 BIGNUM *e = BN_new(); //
 BIGNUM *m = BN_new(); //The message in ascii
 BIGNUM *sig_ver = BN_new(); //verification of the signature

//Initialize 
BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); 
BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D"); 
BN_hex2bn(&e, "010001"); 
BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");

// verify signatue *decryption eith sender's public key* 
BN_mod_exp(sig_ver, S, e, n, ctx); 

printBN("The verification of the signature is:", sig_ver);
printBN("The signature is:", S);

if (BN_cmp(m, sig_ver) == 0)
	printf("The sender was Bob \n");
else
	printf("The sender was not Bob! DO NO LAUNCH THE MISSILE! \n");

return 0;
}