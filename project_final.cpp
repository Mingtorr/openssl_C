#include<openssl/err.h>
#include "openssl/applink.c"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <conio.h>
#include "openssl/sha.h"
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "openssl/hmac.h"
#define BYTES_SIZE 1024
#define KEY_SIZE 128
#define KEY_LENGTH 2048//읽어 들이는 바이트 수
#define PUB_EXP 3

struct ctr_state {
    unsigned char ivec[16];
    unsigned int num;
    unsigned char ecount[16];
};

size_t count;
AES_KEY key;
int padding = RSA_PKCS1_PADDING;
//unsigned char iv[8] = { 0 };//초기화 벡터
unsigned char iv[8] = { 0x66,0x61,0x63,0x65,0x73,0x65,0x61,0x00 };
unsigned char out[2048] = { 0, };
struct ctr_state state;

unsigned char _RSA_encrypted[256] = { 0, }; // 암호화한 결과를 저장할 공간 

RSA* pri_key = NULL; //서명자 개인키
RSA* pub_key = NULL; //서명자 공개키

void print_encrypt(unsigned char* data, int len);
void _aes_decrypt(unsigned char* indata, unsigned char* outdata, int bytes_read, unsigned char* ckey);
int _aes_counter = 0;

/******************************************* 인증서 생성**************************************************************/

/* Generates a 2048-bit RSA key. */
EVP_PKEY* generate_key()
{
    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey)
    {
        printf("Unable to create EVP_PKEY structure.");
        exit(1);
    }

    /* Generate the RSA key and assign it to pkey. */
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pkey, rsa))
    {
        printf("Unable to generate 2048-bit RSA key.");
        EVP_PKEY_free(pkey);
        exit(1);
    }
    return pkey;
}
/* Generates a self-signed x509 certificate. */
X509* generate_x509(EVP_PKEY* pkey)
{
    /* Allocate memory for the X509 structure. */
    X509* x509 = X509_new();
    if (!x509)
    {
        printf("Unable to create X509 structure.");
        exit(1);
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);
    /* We want to copy the subject name to the issuer name. */
    X509_NAME* name = X509_get_subject_name(x509);
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"MyCompany", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);
    /* Actually sign the certificate with our key. */
    if (!X509_sign(x509, pkey, EVP_sha1()))
    {
        printf("Error signing certificate.");
        X509_free(x509);
        exit(1);
    }
    return x509;
}

void write_to_disk(EVP_PKEY* pkey, X509* x509, int mode)
{
    FILE* pkey_file;
    FILE* x509_file;
    /* Open the PEM file for writing the key to disk. */
    if (mode == 0)
        pkey_file = fopen("alice_pri_key.pem", "wb");
    else
        pkey_file = fopen("bob_pri_key.pem", "wb");
    /* Write the key to disk. */
    PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);

    /* Open the PEM file for writing the certificate to disk. */
    if (mode == 0)
        x509_file = fopen("alice_cert.crt", "wb");
    else
        x509_file = fopen("bob_cert.crt", "wb");
    /* Write the certificate to disk. */
    PEM_write_X509(x509_file, x509);
    fclose(x509_file);
    return;
}

void _mk_cert()
{
    /* Generate the key. */

    EVP_PKEY* alice_pkey = generate_key();
    EVP_PKEY* bob_pkey = generate_key();

    X509* alice_x509 = generate_x509(alice_pkey);
    X509* bob_x509 = generate_x509(bob_pkey);

    write_to_disk(alice_pkey, alice_x509, 0);
    write_to_disk(bob_pkey, bob_x509, 1);
    EVP_PKEY_free(alice_pkey);
    EVP_PKEY_free(bob_pkey);
    X509_free(alice_x509);
    X509_free(bob_x509);
    return;
}

//************************************************ AES ***********************************************************************************************************

void _aes_iv_init()
{
    int i = 0;
    for (i = 0; i < 8; i++)
    {
        iv[i] = rand() % 255;
    }
    return;
}

void _aes_init_ctr(struct ctr_state* state, const unsigned char iv[8]) {
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    memset(state->ivec + 8, 0, 8);
    memcpy(state->ivec, iv, 8);
    return;
}
// encrypt twice  == decrypt

void _aes_encrypt(unsigned char* indata, unsigned char* outdata, int bytes_read, unsigned char* ckey, int mode) {

    int i = 0;
    int mod_len = 0;
    int cnt = 0;
    AES_set_encrypt_key(ckey, KEY_SIZE, &key);

    struct ctr_state state;
    _aes_init_ctr(&state, iv);
    CRYPTO_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num, (block128_f)AES_encrypt);
    memcpy(out, outdata, 2048);
    if (mode == 0)
        printf("Signature encrypted by AES\n\n");
    else if (mode == 1)
        printf("plaintext encrypted by AES\n\n");
    else
        printf("Alice's cert encryted by AES\n\n");
    return;
}
//****************************************************************************** RSA ******************************************************************************
//함수 내부 처리에 사용

unsigned char* _RSA_pub_derypted(unsigned char* hash)
{
    unsigned char decrypted[256] = { 0, }; // 복호화한 결과를 저장할 공간
    RSA_public_decrypt(256, hash, decrypted, pub_key, RSA_PKCS1_PADDING);
    printf("digital signature decrpyted \n");
    print_encrypt(decrypted, 64);
    return decrypted; 
}

void _RSA_pri_encryted(unsigned char* hash, unsigned char* ckey, int mode ) // Hmac 암호화
{
    unsigned char  encrypted[256] = { 0 }; // 암호화한 결과를 저장할 공간 
    RSA_private_encrypt(64, hash, encrypted, pri_key, RSA_PKCS1_PADDING);
    printf("digital signature_encryt : \n");
    print_encrypt(encrypted, 256);
    _aes_encrypt(encrypted, encrypted, 256, ckey, mode);
    return;
}

unsigned char* _RSA_pri_decryted(unsigned char* data)
{
    unsigned char  decrypted[256] = { 0 }; // 암호화한 결과를 저장할 공간 
    RSA_private_decrypt(256, data, decrypted, pri_key, RSA_PKCS1_PADDING);
    printf("AES's key decrypted \n");
    return decrypted;
}
unsigned char* _RSA_pub_encrypted(unsigned char* data)
{
    unsigned char  encrypted[256] = { 0 }; // 암호화한 결과를 저장할 공간 
    int len =RSA_public_encrypt(18,data, encrypted, pub_key, RSA_PKCS1_PADDING);
    if (len == -1)
    {
        printf("no");
        exit(1);
    }
    printf("AES's key encrypted by RSA \n\n");
    return encrypted;
}
//****************************************************************************** HMAC ******************************************************************************
unsigned char* _hmac(unsigned char* data, int size, int mode, unsigned char* ckey )//hmac 함수
{
    unsigned char* key = (unsigned char*)"This is your secret"; //hmac key
    unsigned char* result;
    int result_len = 64; //sha-512 64bit 
    int i;
    static char res_hexstring[64];

    result = HMAC(EVP_sha512(), key, strlen((char*)key), data, size, NULL, NULL);
    printf("HASH Mac Completed!!\n");
    printf("hash MAC: \n");
    print_encrypt(result, 64);

    if (mode == 0)
        _RSA_pri_encryted(result, ckey, mode); // 서명 실행
    return result;
}
void print_encrypt(unsigned char* data, int len)
{
    static char res_hexstring[256];
    int i = 0;
    for (i = 0; i < len; i++) {
        sprintf(&(res_hexstring[i * 2]), "%02x", data[i]);
    }
    printf("%s \n\n", res_hexstring);
    return;
}
//****************************************************************************************************************
void command_encrypt()
{
    unsigned char ckey[] = "thiswillbeyourkey"; // It is 128bits though..
    
    FILE* fp = fopen("plaintext.txt", "a+b");
    FILE* op = fopen("ciphertext.txt", "r+b");
    FILE* crtf= fopen("alice_cert.crt", "r+"); //사용자 인증서 파일 오픈
    FILE* alice_pri = fopen("alice_pri_key.pem", "r");
    FILE* bob_pub = fopen("bob_cert.crt", "r");

    if (fp == NULL) { fputs("File error", stderr); exit(1); }
    
    X509* user_x509 = NULL;
    EVP_PKEY* e_pub_key = NULL; //서명자 인증서

    unsigned char crt[2048] = { 0, }; // Alice 의 인증서
    unsigned char key[256] = { 0 };  // AES KEY 암호화
    unsigned char buffer[256] = { 0, }; // Plaintext 읽어오기
    
    pri_key = PEM_read_RSAPrivateKey(alice_pri, NULL, NULL, NULL); // 파일로부터 RSA용 개인키를 로드한다.
    user_x509 = PEM_read_X509(bob_pub, NULL, NULL, NULL);
    e_pub_key = X509_get_pubkey(user_x509);// 사용자 x509v3 타입의 인증서로부터 공개키를 추출한다.
    pub_key = EVP_PKEY_get1_RSA(e_pub_key);// 추출한 공개키로부터 RSA용 공개키를 가져온다.
    
    //개인키 : 앨리스의 개인키, 공개키: 밥의 공개키
    
    fseek(op, 0, SEEK_SET);
    fread(buffer, 256, 1, fp);    
    printf("plaintext = %s \n\n", buffer);
    _hmac(buffer, 256, 0,ckey); //hmac 및 디지털 서명 및 aes 암호화
    fwrite(out, 1, 1024, op); //hmac 및 디지털 서명 및 aes 암호화 결과 쓰기

    _aes_encrypt(buffer, buffer, 256,ckey, 1);  //원문 AES 암호화
    fwrite(out, 1, 1024, op); //원문 aes암호화 결과 쓰기
    
    fread(crt, 1, 2048, crtf);
    _aes_encrypt(crt, crt, 512,ckey,2);  //alice 인증서 AES 암호화
    fwrite(out, 1, 2048, op); //alice 인증서 aes 암호화 결과 쓰기
    memcpy(key,_RSA_pub_encrypted(ckey),256);
    fwrite(key, 1, 1024, op); //키 rsa 암호화 결과 쓰기
   
    printf(" plaintext encrpyted!!!\n\n");
    printf("--------------------------------------\n");
    fclose(fp);
    fclose(op);
    fclose(crtf);
    fclose(alice_pri);
    fclose(bob_pub);
    return;
}

void command_decrypt()
{
    FILE* op = fopen("ciphertext.txt", "r+b");
    FILE* rp = fopen("recovertext.txt", "r+b");
    FILE* crtf;
    if (op == NULL) { fputs("File error", stderr); exit(1); }
    FILE* bob_pri = fopen("bob_pri_key.pem", "r");
    unsigned char signature[1024] = { 0, };
    unsigned char plain[1024] = { 0, };
    unsigned char _cert[2048] = { 0, };
    unsigned char ckey[1024] = { 0, };
    

    X509* user_x509 = NULL;
    EVP_PKEY* e_pub_key = NULL; //서명자 인증서

    pri_key = PEM_read_RSAPrivateKey(bob_pri, NULL, NULL, NULL); // 파일로부터 RSA용 개인키를 로드한다.
    
    fseek(op, 0, SEEK_SET);
    fread(signature, 1, 1024, op);
    fread(plain, 1, 1024, op);
    fread(_cert, 1, 2048, op);
    fread(ckey, 1, 1024, op);
    
    memcpy(ckey,_RSA_pri_decryted(ckey), 256); // AES 키 복호화
    
    _aes_encrypt(_cert, _cert, 512,ckey,2);
    printf(" %s\n", out);
    crtf= fopen("decrypted_alice_cert.crt", "w+b"); //사용자 인증서 파일 오픈
    fwrite(out, 2048, 1, crtf);
    rewind(crtf);
    user_x509 = PEM_read_X509(crtf, NULL, NULL, NULL);
    e_pub_key = X509_get_pubkey(user_x509);// 사용자 x509v3 타입의 인증서로부터 공개키를 추출한다.
    pub_key = EVP_PKEY_get1_RSA(e_pub_key);// 추출한 공개키로부터 RSA용 공개키를 가져온다.
    //인증서 복호화 완료

    _aes_encrypt(plain, plain, 256,ckey,1);
    printf(" %s \n\n ", out);
    _aes_encrypt(signature,signature, 256,ckey,0);
    print_encrypt(signature, 256);
    _hmac(plain, 256, 1,ckey);
    _RSA_pub_derypted(signature);
    
    printf("decrypting success \n");
    printf("decrypted message = %s \n\n", plain);
    fclose(op);
    fclose(rp);
    fclose(crtf);
    fclose(bob_pri);
    return;
}

int main()
{
    int i;
    int tmp =0;
    srand((unsigned int)time(NULL));
    _aes_iv_init();
    _mk_cert();
    
    while(1)
    {
        printf("1. Encrypt 2. Decrypt 3. Exit\n");
        if (scanf_s("%d", &i) == 0)
        {
            printf("숫자를 입력해야 합니다\n");
            rewind(stdin);
        }
        if (i == 1)
        {
            tmp = 1;
            command_encrypt();
        }
            
        else if (i == 2)
        {
            if (tmp != 1)
            {
                printf("먼저 암호화 하세요!!!\n\n");
                continue;
            }
            command_decrypt();
        }
        else if (i == 3)
            exit(1);
        else
            printf("Wrong input!!\n\n");
    }
    return 0;
}
