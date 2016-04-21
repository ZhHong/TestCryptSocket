#include <stdio.h>
#include "Crypt.h"
#include <iostream>
#include <string>
#include <assert.h>
#include "ODSocket.h"
#define MSGSIZE 1024
#define SERVER_ADDRESS "192.168.136.128"
#define WORK_SERVER_ADDRESS "127.0.0.1"
#define PORT           5188

using namespace std;

int main(void) {
	ODSocket odsc;
	bool a=odsc.Connect(WORK_SERVER_ADDRESS, PORT);
	if (!a){
		printf("connect %s:%d field!\n", WORK_SERVER_ADDRESS, PORT);
	}
	else{
		printf("connect %s:%d success!\n", WORK_SERVER_ADDRESS, PORT);
		//connect success get server chanlllage
		char chanllage[MSGSIZE];
		int lenr1 = odsc.Recv(chanllage, strlen(chanllage), 0);
		//recive data [0] msg_type [1] msg_len

		//random key
		char private_key[8];
		char public_key[8];
		Crypt::randomkey(private_key);
		Crypt::dhexchange(public_key);


		//change base64 char
		char base64_public_key[16];
		Crypt::base64encode((const uint8_t *)public_key, base64_public_key);
		char senddata[14];
		senddata[0] = 0;
		senddata[1] = 12;
		for (int i = 2; i < 14; i++){
			senddata[i] = base64_public_key[i - 2];
		}
		//send public key to server
		int lens1 = odsc.Send(senddata, strlen(base64_public_key), 0);
		
		//revice server public key
		char server_public_key[MSGSIZE];
		int lenr2 = odsc.Recv(server_public_key, strlen(server_public_key), 0);
		//todo NOT remove head
		int rev_le = (int)server_public_key[1];
		char needServerKey[12];
		for (int m = 0; m < rev_le; m++){
			needServerKey[m] = server_public_key[m + 2];
		}
		char base64_server_public_key[16];
		Crypt::base64decode((const uint8_t *)needServerKey, base64_server_public_key);
		//compute secret
		char secret[16];
		int sec_len = server_public_key[1];
		char useServerkey[12];
		for (int j = 0; j < sec_len; j++){
			useServerkey[j] = server_public_key[j + 2];
		}
		Crypt::dhsecret(useServerkey, private_key, secret);
		char out[16];
		Crypt::hexencode((const uint8_t *)secret, out);
		//crypt chanllage

		//send chanllage

		//send token
		
		//get result

	}
	system("pause");
	return 0;
}
