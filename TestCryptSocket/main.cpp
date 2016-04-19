#include <stdio.h>
#include "Crypt.h"
#include <iostream>
#include <string>
#include <assert.h>

#include <WinSock2.h>
#define MSGSIZE 1024
#define SERVER_ADDRESS "127.0.0.1"
#define PORT           5188
#pragma comment(lib,"ws2_32.lib")

using namespace std;
//aes
static const unsigned char sbox[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
	0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
	0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
	0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
	0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
	0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
	0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
	0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
	0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
	0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
	0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
	0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
	0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
	0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
	0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
	0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
	0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const unsigned char contrary_sbox[256] = {
	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
	0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
	0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,
	0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0xe4,
	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,
	0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
	0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,
	0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,
	0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
	0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,
	0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,
	0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
	0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,
	0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,
	0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
	0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,
	0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,
	0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

//The key schedule rcon table
static const unsigned char Rcon[10] = {
	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

//the xtime(0 function)
static unsigned char
xtime(unsigned char x) {
	if (x & 0x80) {
		return(((x << 1) ^ 0x1B) & 0xFF);
	}
	return x << 1;
}

//mixcolumns:Process the entire block
static void
MixColumns(unsigned char *col) {
	unsigned char temp[4], xt[4];
	int x;

	for (x = 0; x<4; x++, col += 4) {
		xt[0] = xtime(col[0]);
		xt[1] = xtime(col[1]);
		xt[2] = xtime(col[2]);
		xt[3] = xtime(col[3]);
		temp[0] = xt[0] ^ xt[1] ^ col[1] ^ col[2] ^ col[3];
		temp[1] = col[0] ^ xt[1] ^ xt[2] ^ col[2] ^ col[3];
		temp[2] = col[0] ^ col[1] ^ xt[2] ^ xt[3] ^ col[3];
		temp[3] = xt[0] ^ col[0] ^ col[1] ^ col[2] ^ xt[3];
		col[0] = temp[0]; col[1] = temp[1]; col[2] = temp[2];
		col[3] = temp[3];
	}
}

static void
Contrary_MixColums(unsigned char *col) {
	unsigned char tmp[4];
	unsigned char xt2[4];
	unsigned char xt4[4];
	unsigned char xt8[4];
	int x;
	for (x = 0; x<4; x++, col += 4) {
		xt2[0] = xtime(col[0]);
		xt2[1] = xtime(col[1]);
		xt2[2] = xtime(col[2]);
		xt2[3] = xtime(col[3]);
		xt4[0] = xtime(xt2[0]);
		xt4[1] = xtime(xt2[1]);
		xt4[2] = xtime(xt2[2]);
		xt4[3] = xtime(xt2[3]);
		xt8[0] = xtime(xt4[0]);
		xt8[1] = xtime(xt4[1]);
		xt8[2] = xtime(xt4[2]);
		xt8[3] = xtime(xt4[3]);
		tmp[0] = xt8[0] ^ xt4[0] ^ xt2[0] ^ xt8[1] ^ xt2[1] ^ col[1] ^ xt8[2] ^ xt4[2] ^ col[2] ^ xt8[3] ^ col[3];
		tmp[1] = xt8[0] ^ col[0] ^ xt8[1] ^ xt4[1] ^ xt2[1] ^ xt8[2] ^ xt2[2] ^ col[2] ^ xt8[3] ^ xt4[3] ^ col[3];
		tmp[2] = xt8[0] ^ xt4[0] ^ col[0] ^ xt8[1] ^ col[1] ^ xt8[2] ^ xt4[2] ^ xt2[2] ^ xt8[3] ^ xt2[3] ^ col[3];
		tmp[3] = xt8[0] ^ xt2[0] ^ col[0] ^ xt8[1] ^ xt4[1] ^ col[1] ^ xt8[2] ^ col[2] ^ xt8[3] ^ xt4[3] ^ xt2[3];
		col[0] = tmp[0];
		col[1] = tmp[1];
		col[2] = tmp[2];
		col[3] = tmp[3];
	}
}

//shiftrows: shifts the entire block
static void
ShiftRows(unsigned char *col) {
	unsigned char t;
	//2nd row
	t = col[1];
	col[1] = col[5];
	col[5] = col[9];
	col[9] = col[13];
	col[13] = t;
	//3rd row
	t = col[2]; col[2] = col[10]; col[10] = t;
	t = col[6]; col[6] = col[14]; col[14] = t;
	//4th row
	t = col[15]; col[15] = col[11]; col[11] = col[7];
	col[7] = col[3]; col[3] = t;
}

static void
Contrary_ShiftRows(unsigned char *col) {
	unsigned char t;
	/*2ndrow*/
	t = col[13]; col[13] = col[9]; col[9] = col[5];
	col[5] = col[1]; col[1] = t;
	/*3rdrow*/
	t = col[2]; col[2] = col[10]; col[10] = t;
	t = col[6]; col[6] = col[14]; col[14] = t;
	/*4throw*/
	t = col[3]; col[3] = col[7]; col[7] = col[11];
	col[11] = col[15]; col[15] = t;
}

//subbytes
static void
SubBytes(unsigned char *col) {
	int x;
	for (x = 0; x<16; x++) {
		col[x] = sbox[col[x]];
	}

}

static void
Contrary_SubBytes(unsigned char *col) {
	int x;
	for (x = 0; x<16; x++) {
		col[x] = contrary_sbox[col[x]];
	}
}

//addRoundKey
static void
AddRoundKey(unsigned char *col, unsigned char *key, int round) {
	int x;
	for (x = 0; x<16; x++) {
		col[x] ^= key[(round << 4) + x];
	}
}

static void
AesEncrypt(unsigned char * blk, unsigned char *key, int Nr) {
	int x;

	AddRoundKey(blk, key, 0);
	for (x = 1; x <= (Nr - 1); x++) {
		SubBytes(blk);
		ShiftRows(blk);
		MixColumns(blk);
		AddRoundKey(blk, key, x);
	}
	SubBytes(blk);
	ShiftRows(blk);
	AddRoundKey(blk, key, Nr);
}

static void
Contrary_AesEncrypt(unsigned char *blk, unsigned char *key, int Nr) {
	int x;
	AddRoundKey(blk, key, Nr);
	Contrary_ShiftRows(blk);
	Contrary_MixColums(blk);
	Contrary_SubBytes(blk);
	for (x = (Nr - 1); x >= 1; x --) {
		AddRoundKey(blk, key, x);
		Contrary_MixColums(blk);
		Contrary_ShiftRows(blk);
		Contrary_SubBytes(blk);
	}
	AddRoundKey(blk, key, 0);
}

static void
ScheduleKey(unsigned char *inkey, unsigned char *outkey, int Nk, int Nr) {
	unsigned char temp[4], t;
	int x, i;
	for (i = 0; i<(4 * Nk); i++) {
		outkey[i] = inkey[i];
	}
	i = Nk;
	while (i<(i*(Nr + 1))) {
		for (x = 0; x<4; x++) {
			temp[x] = outkey[((i - 1) << 2) + x];
		}
		if (i%Nk == 0) {
			/*RotWord()*/
			t = temp[0]; temp[0] = temp[1];
			temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
			/*SubWord()*/
			for (x = 0; x<4; x++) {
				temp[x] = sbox[temp[x]];
			}
			temp[0] ^= Rcon[(i / Nk) - 1];

		}
		else if (Nk>6 && (i %Nk) == 4) {
			for (x = 0; x<4; x++) {
				temp[x] = sbox[temp[x]];
			}
		}
		/*w[i]=w[i-Nk] xortemp*/
		for (x = 0; x<4; x++) {
			outkey[(i << 2) + x] = outkey[((i - Nk) << 2) + x] ^ temp[x];
		}
		++i;
	}
}

int main(void) {
	//unsigned char pt[17], key[17];
	//unsigned char skey[15 * 16];
	//int i;
	//int j;
	//printf("pleaseinputplaintext\n");//输入无格式的字符串 字符个数不得少于六个！！！！尽 量用不同的数字或字母 
	//scanf("%s", pt);
	//printf("pleaseinputkey\n");//输入加密钥匙 密匙个数不得低于六个！！！！ 尽量用不同的数字或字母
	//scanf("%s", key);
	//ScheduleKey(key, skey, 4, 10); //密钥编排
	//AesEncrypt(pt, skey, 10);//AES 加密 
	//printf("Ciphertestis:");//输出密码文件 
	//for (i = 0; i < 16; i++) {
	//	printf("%02x", pt[i]);
	//}
	//printf("\n"); printf("\n");
	//printf("the64sboxnumber:\n");
	//for (j = 1; j < 65; j++) {
	//	printf("%02x", sbox[j - 1]);
	//	if (!(j % 10)) {
	//		printf("\n");
	//	}
	//}
	//printf("\n"); printf("\n");
	//Contrary_AesEncrypt(pt, skey, 10);//AES 解密
	//printf("afterContrary_AesEncrypt,plaintextis:");//将解密文件输出 
	//for (i = 0; i < 16; i++) {
	//	printf("%c", pt[i]);
	//}
	//printf("\n"); printf("\n");

	//scanf("%s", key);
	char prikey[8];
	char pubkey[8];
	Crypt::randomkey(prikey);
	Crypt::dhexchange(pubkey);

	char b64prikey[8];
	char b64pubkey[8];
	Crypt::base64encode((const uint8_t *)prikey, b64prikey);
	Crypt::base64encode((const uint8_t *)pubkey, b64pubkey);

	char prikey1[8];
	char pubkey1[8];
	Crypt::randomkey(prikey1);
	Crypt::dhexchange(pubkey1);
	char secret1[8];
	char secret2[8];

	Crypt::dhsecret(pubkey1, prikey, secret1);
	Crypt::dhsecret(pubkey, prikey1, secret2);
	char out1[17];
	char out2[17];
	Crypt::hexencode((const uint8_t *)secret1, out1);
	Crypt::hexencode((const uint8_t *)secret2, out2);
	//assert(secret1 == secret2);
	out1[16] = '\0';
	out2[16] = '\0';
	std::string s1 = (string)out1;
	std::string s2 = (string)out2;
	
	printf("secret 1 %s\n", s1);
	printf("secret 2 %s\n", s2);
	if (s1 == s2) {
		printf("secret match %s\n",secret1);
	}

	system("pause");

	WSADATA wsaData;
	SOCKET sclient;
	SOCKADDR_IN server;
	char szMessage[MSGSIZE];
	int ret;
	// Initialize Windows socket library
	WSAStartup(0x0202, &wsaData);
	//create client socket
	sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	// Connect to server
	memset(&server, 0, sizeof(SOCKADDR_IN));
	server.sin_family = AF_INET;
	server.sin_addr.S_un.S_addr = inet_addr(SERVER_ADDRESS);
	server.sin_port = htons(PORT);
	connect(sclient, (struct sockaddr *)&server, sizeof(SOCKADDR_IN));
	//while connet get changelle
	char changelle[MSGSIZE];
	ret = recv(sclient, changelle, MSGSIZE, 0); //5FpsARFeNy8 =
	
	char prikey_c[8];
	char pubkey_c[8];
	Crypt::randomkey(prikey);
	Crypt::dhexchange(pubkey);
	send(sclient, pubkey_c, strlen(prikey_c), 0);
	char server_key[MSGSIZE];
	ret = recv(sclient, server_key, strlen(server_key), 0);

	char secret_s[17];
	char out3[17];
	Crypt::dhsecret(server_key, prikey_c, secret_s);
	Crypt::hexencode((const uint8_t *)secret_s, out3);
	out3[16] = '\0';
	std::string s3 = (string)out3;
	//
	//while (TRUE)
	//{
	//	printf("Send:");
	//	gets(szMessage);
	//	// Send message
	//	send(sclient, szMessage, strlen(szMessage), 0);
	//	// Receive message
	//	ret = recv(sclient, szMessage, MSGSIZE, 0);
	//	szMessage[ret] = '\0';
	//	printf("Received [%d bytes]: '%s'\n", ret, szMessage);
	//}
	// Clean up
	closesocket(sclient);
	WSACleanup();
	return 0;
}
