#include <ucx.h>
//#include <assert.h>
void xtea_encrypt(uint32_t v[2], const uint32_t key[4], uint32_t num_rounds);
void xtea_decrypt(uint32_t v[2], const uint32_t key[4], uint32_t num_rounds);
void xtea_cbc_encrypt(uint8_t *out, uint8_t *in, uint32_t len, const uint32_t key[4], const uint32_t iv[2]);
void xtea_cbc_decrypt(uint8_t *out, uint8_t *in, uint32_t len, const uint32_t key[4], const uint32_t iv[2]);
void build_enc_request(char* msg, char*buf);
void build_dec_request(char* msg, char*buf);
void build_res_request(char* msg, char*buf);

struct pipe_s *request_pipe, *decrypt_pipe, *result_pipe;

void req_handler()
{
	uint8_t message[128];
	char res_buf[128];
	char *str;

    for (;;) {
        memset(message, 0, sizeof(message));
        while (ucx_pipe_size(request_pipe) < 1);

	    ucx_pipe_read(request_pipe, message, ucx_pipe_size(request_pipe));
		printf("depois do pipe: %s\n", message);

		str = strtok(message, " ");
		if(strcmp(str, "enc")==0) {
			printf("encrypt\n");
			str = strtok(NULL, " ");
			hextoascii(message, str);
			printf("messageInAscii: %s\n", message);
			encrypt(message, res_buf);
			printf("res_buf: %s, len: %d\n", res_buf, strlen(res_buf));
			//ucx_task_suspend(1);
			ucx_pipe_write(result_pipe, res_buf, strlen(res_buf));
			//ucx_task_resume(1);
			
		}else if(strcmp(str, "dec")==0) {
			printf("decrypt\n");
			str = strtok(NULL, " ");
			hextoascii(message, str);
			//printf("Encrypted message InAscii: %s\n", message);
			//decrypt(message, res_buf);
			printf("res_buf: %s, len: %d\n", res_buf, strlen(res_buf));
			//ucx_task_suspend(1);
			ucx_pipe_write(result_pipe, res_buf, strlen(res_buf));
			//ucx_task_resume(1);

		}
		//hextoascii(msg_to_encrypt, str);
	    //printf("message: %s\n", msg_to_encrypt);
//
	    //uint32_t xtea_key[4] = {0xf0e1d2c3, 0xb4a59687, 0x78695a4b, 0x3c2d1e0f};
	    //uint32_t iv[2] = {0x11223344, 0x55667788};
		//
        //xtea_cbc_encrypt(encrypted_msg, msg_to_encrypt, sizeof(msg_to_encrypt), xtea_key, iv);
	    //printf("\nencoded message (CBC mode): %s\n", encrypted_msg);
		//string2hexString(encrypted_msg, message);
		////transformar o encrypted_msg de volta para hex
		//char *aux = (char *)malloc(sizeof(encrypted_msg)*2 + 10);
	    //printf("\nencoded message in hex: %s\n", message);
		//sprintf(aux,"res ");
		//strcat(aux, message);
		//strcat(aux, " end");
	    //printf("\nencoded message in hex + res end: %s\n", message);

		//ucx_pipe_write(result_pipe, message, strlen(message));
		//free(aux);
		//free(message);
		//free(str);
		//free(res_buf);
		//free(msg_to_encrypt);
	    //xtea_cbc_decrypt(message, message, sizeof(message), xtea_key, iv);
	    //printf("\ndecoded message (CBC mode): %s\n", message);
		

    }
}

void task0(void)
{
    char message[] = "the quick brown fox jumps over the lazy dog";
	char *decryptedMessage = (char *)malloc(200);
	char *encryptedMessage = (char *)malloc(200);
	char *resInAscii = (char *)malloc(200);
	char *dec_request = (char *)malloc(200);
	char *hexifiedMsgAux = (char *)malloc(200);
	char *hexifiedMsg = (char *)malloc(200);

	while (1) {
		/* write pipe - write size must be less than buffer size */
		string2hexString(message, hexifiedMsgAux);
		sprintf(hexifiedMsg,"enc ");
		strcat(hexifiedMsg, hexifiedMsgAux);
		strcat(hexifiedMsg, " end");
		printf("antes do pipe: %s\n", hexifiedMsg);
		ucx_pipe_write(request_pipe, hexifiedMsg, strlen(hexifiedMsg));
		
		//for (;;);
        while (ucx_pipe_size(result_pipe) < 1);
		_delay_ms(2);
	    ucx_pipe_read(result_pipe, encryptedMessage, ucx_pipe_size(result_pipe));

		encryptedMessage = strtok(encryptedMessage, " ");
		encryptedMessage = strtok(NULL, " ");
		printf("resultado: %s\n", encryptedMessage);

		printf("resultado len(): %d\n", strlen(encryptedMessage));

		hextoascii(resInAscii, encryptedMessage);

		//printf("Resultado em ascii: %s\n", resInAscii);
		sprintf(dec_request,"dec ");
		strcat(dec_request, encryptedMessage);
		strcat(dec_request, " end");

		printf("dec request: %s\n", dec_request);

		ucx_pipe_write(request_pipe, dec_request, strlen(dec_request));

		//free(hexifiedMsg);
		//free(hexifiedMsgAux);
		//free(encryptedMessage);
	}
}

//void decrypt(char *encrypted_msg_in, char *decrypted_msg_out)
//{
//	char *aux = (char *)malloc(128);
//	strcpy(aux, encrypted_msg_in);
//	uint32_t xtea_key[4] = {0xf0e1d2c3, 0xb4a59687, 0x78695a4b, 0x3c2d1e0f};
//	uint32_t iv[2] = {0x11223344, 0x55667788};
//	
//    xtea_cbc_decrypt(decrypted_msg_out, encrypted_msg_in, strlen(encrypted_msg_in), xtea_key, iv);
//
//	string2hexString(msgCopy, msg); //encrypted to hex
//	sprintf(enc_msg,"res "); //add response tokens
//	strcat(enc_msg, msg);
//	strcat(enc_msg, " end");
//	//printf("encrypt func: %d\n", enc_msg);
//	free(msgCopy);
//}

void encrypt(char *msg, char *enc_msg)
{
	char *msgCopy = (char *)malloc(sizeof(msg));
	strcpy(msgCopy, msg);
	uint32_t xtea_key[4] = {0xf0e1d2c3, 0xb4a59687, 0x78695a4b, 0x3c2d1e0f};
	uint32_t iv[2] = {0x11223344, 0x55667788};
	
    xtea_cbc_encrypt(msgCopy, msg, strlen(msg), xtea_key, iv); //encrypt
	string2hexString(msgCopy, msg); //encrypted to hex
	sprintf(enc_msg,"res "); //add response tokens
	strcat(enc_msg, msg);
	strcat(enc_msg, " end");
	//printf("encrypt func: %d\n", enc_msg);
	free(msgCopy);
	
}


void hextoascii(char *dest, char *src) {
	char tmp;
	while (*src) {
		if (*src<58) {
			tmp = (*src - 48) << 4;
		}else {
			tmp = (*src - 87) << 4;
		}
		if (*++src < 58) {
			tmp |= (*src - 48);
		}else {
			tmp |= (*src - 87);
		}
		src++;
		*dest++ = tmp;
	}
	*dest = '\0';
}

void hextostr(char *dest, const char *src) {
    static unsigned char const val[(unsigned char)-1+1] = {
        ['0'] =  0+1, ['1'] =  1+1, ['2'] =  2+1, ['3'] =  3+1, ['4'] =  4+1,
        ['5'] =  5+1, ['6'] =  6+1, ['7'] =  7+1, ['8'] =  8+1, ['9'] =  9+1,
        ['a'] = 10+1, ['b'] = 11+1, ['c'] = 12+1, ['d'] = 13+1, ['e'] = 14+1, ['f'] = 15+1,
        ['A'] = 10+1, ['B'] = 11+1, ['C'] = 12+1, ['D'] = 13+1, ['E'] = 14+1, ['F'] = 15+1,
    };
    const unsigned char *p = (const unsigned char *)src;
    while (val[p[0]] && val[p[1]]) {
        *dest++ = (char)(val[p[0]] * 16 + val[p[1]] - 17);
        p += 2;
    }
    *dest = '\0';
}

void string2hexString(char* input, char* output)
{
	while(*input) {
		*output = (*input >> 4) & 0xf;
		if(*output < 10) {
			*output += 48;
		}else{
			*output += 87;
		}
		output++;
		*output = *input & 0xf;
		if(*output < 10) {
			*output += 48;
		}else{
			*output += 87;
		}
		output++;
		input++;
	}
	*output = '\0';
}


int32_t app_main(void)
{
	ucx_task_add(req_handler, DEFAULT_STACK_SIZE);
	ucx_task_add(task0, DEFAULT_STACK_SIZE);

	request_pipe = ucx_pipe_create(256);		/* pipe buffer, 128 bytes (allocated on the heap) */
	decrypt_pipe = ucx_pipe_create(256);		/* pipe buffer, 64 bytes */
	result_pipe = ucx_pipe_create(256);
	// start UCX/OS, preemptive mode
	return 1;
}

void xtea_encrypt(uint32_t v[2], const uint32_t key[4], uint32_t num_rounds)
{
	uint32_t i;
	uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;

	for (i = 0; i < num_rounds; i++){
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
		sum += delta;
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
	}
	v[0] = v0; v[1] = v1;
}

void xtea_decrypt(uint32_t v[2], const uint32_t key[4], uint32_t num_rounds)
{
	uint32_t i;
	uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;

	for (i = 0; i < num_rounds; i++){
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
		sum -= delta;
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
	}
	v[0] = v0; v[1] = v1;
}


/* XTEA stream cipher, CBC mode
 * CBC mode based on https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
 */
#define BLOCKLEN	8		// in bytes

void xtea_cbc_encrypt(uint8_t *out, uint8_t *in, uint32_t len, const uint32_t key[4], const uint32_t iv[2])
{
	uint32_t i, rem, block[2], tiv[2];
	
	rem = len % BLOCKLEN;
	tiv[0] = iv[0];
	tiv[1] = iv[1];
	for (i = 0; i < len; i += BLOCKLEN) {
		memcpy((char *)block, in, BLOCKLEN);
		block[0] ^= tiv[0];
		block[1] ^= tiv[1];
		xtea_encrypt(block, key, 32);
		tiv[0] = block[0];
		tiv[1] = block[1];
		memcpy(out, (char *)block, BLOCKLEN);
		in += BLOCKLEN;
		out += BLOCKLEN;
	}
	if (rem) {
		memcpy((char *)block, in, BLOCKLEN - rem);
		memset((char *)block + rem, 0, BLOCKLEN - rem);
		block[0] ^= tiv[0];
		block[1] ^= tiv[1];
		xtea_encrypt(block, key, 32);
		memcpy(out, (char *)block, BLOCKLEN - rem);
	}
}

void xtea_cbc_decrypt(uint8_t *out, uint8_t *in, uint32_t len, const uint32_t key[4], const uint32_t iv[2])
{
	uint32_t i, rem, block[2], block2[2], tiv[2];
	
	rem = len % BLOCKLEN;
	tiv[0] = iv[0];
	tiv[1] = iv[1];
	for (i = 0; i < len; i += BLOCKLEN) {
		memcpy((char *)block, in, BLOCKLEN);
		block2[0] = block[0];
		block2[1] = block[1];
		xtea_decrypt(block, key, 32);
		block[0] ^= tiv[0];
		block[1] ^= tiv[1];
		tiv[0] = block2[0];
		tiv[1] = block2[1];
		memcpy(out, (char *)block, BLOCKLEN);
		in += BLOCKLEN;
		out += BLOCKLEN;
	}
	if (rem) {
		memcpy((char *)block, in, BLOCKLEN - rem);
		memset((char *)block + rem, 0, BLOCKLEN - rem);
		tiv[0] = block[0];
		tiv[1] = block[1];
		xtea_decrypt(block, key, 32);
		block[0] ^= tiv[0];
		block[1] ^= tiv[1];
		memcpy(out, (char *)block, BLOCKLEN - rem);
	}
}
