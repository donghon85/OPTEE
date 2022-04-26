/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	// ceaser variable
	char plainText[64] = {0,}; 
	char cipherText[64] = {0,};
	int len = 64;
	char encryptedText[64] = {0,};
	char encryptedKey[64] = {0,};

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	if (!strcmp(argv[3], "Ceaser")){
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plainText;
	op.params[0].tmpref.size = len;
	op.params[1].value.a = 0; // encodedKey storage space

	if (!strcmp(argv[1], "-e")){ // if argv[1] == -e, then run encode 
		printf("=============================Encode=============================\n");
		FILE *file = fopen(argv[2], "r"); // file open 
		if (file == NULL){ // check fileopen error
			printf("File Error\n");
			return 0;
		}
		fgets(plainText, sizeof(plainText), file); 
		// initailizes contents of file in plainText
		fclose(file);

		memcpy(op.params[0].tmpref.buffer, plainText, len);
		// initialize the plainText value in op.params[0].temref.buffer
		printf("plainText : %s", plainText); 
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		// run encodeing of TEEencrypt
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
	
		memcpy(cipherText, op.params[0].tmpref.buffer, len);
		// initialize encrypted statement in cipherText

		printf("Encoded text : %s\n", cipherText);
		printf("encodedkey : %d\n", op.params[1].value.a);
	
		FILE *encodeFile = fopen("encodedFile.txt", "w+"); // create encodedFile
		fwrite(cipherText, strlen(cipherText), 1, encodeFile); // write the contents in a file
		fprintf(encodeFile, "%d\n", op.params[1].value.a); // write the encodedKey in a file
		fclose(encodeFile);
	}
	else if (!strcmp(argv[1], "-d")){ // if argv[1] == -d, then run decode 
		printf("=============================Decode=============================\n");
		FILE *file = fopen(argv[2], "r");
		if (file == NULL){
			printf("File error\n");
			return 0;
		}
		fgets(encryptedText, sizeof(encryptedText), file); 
		// initialize encryted contents of file in encryptedText
		fgets(encryptedKey, sizeof(encryptedKey), file);
		// initialize encryted key of file in encryptedKey
		fclose(file);

		memcpy(op.params[0].tmpref.buffer, encryptedText, len);
		// initialize the encryptedText in op.params[0].temref.buffer
		op.params[1].value.a = atoi(encryptedKey); // bring encryptedKey to TEE
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin); // run Decodeing of TEEencrypt 
		if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
		memcpy(cipherText, op.params[0].tmpref.buffer, len);
		// initialize decrypted statement in cipherText
		printf("Decoded Text : %s\n", cipherText);
		
		FILE *decodeFile = fopen("decodedFile.txt", "w+"); // creat decodedFile
		fwrite(cipherText, strlen(cipherText), 1, decodeFile); // write the contents in file
		fclose(decodeFile);
	}
	
	
}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
