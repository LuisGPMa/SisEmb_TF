#include <ucx.h>
//#include <assert.h>
#define XTEA_BASE			0xe7000000
#define XTEA_CONTROL			(*(volatile uint32_t *)(XTEA_BASE + 0x000))
#define XTEA_KEY0			(*(volatile uint32_t *)(XTEA_BASE + 0x010))
#define XTEA_KEY1			(*(volatile uint32_t *)(XTEA_BASE + 0x020))
#define XTEA_KEY2			(*(volatile uint32_t *)(XTEA_BASE + 0x030))
#define XTEA_KEY3			(*(volatile uint32_t *)(XTEA_BASE + 0x040))
#define XTEA_IN0			(*(volatile uint32_t *)(XTEA_BASE + 0x050))
#define XTEA_IN1			(*(volatile uint32_t *)(XTEA_BASE + 0x060))
#define XTEA_OUT0			(*(volatile uint32_t *)(XTEA_BASE + 0x070))
#define XTEA_OUT1			(*(volatile uint32_t *)(XTEA_BASE + 0x080))
#define XTEA_START			(1 << 0)
#define XTEA_ENCRYPT			(1 << 1)
#define XTEA_DECRYPT			(0 << 1)
#define XTEA_READY			(1 << 2)

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
	char enc_res_buf[128];
	char dec_res_buf[128];
	char *str = (char *)malloc(128);
	//char *msg_buf_ecb = (char *)malloc(200);

    for (;;) {
        memset(message, 0, sizeof(message));
        memset(enc_res_buf, 0, sizeof(enc_res_buf));
        memset(dec_res_buf, 0, sizeof(dec_res_buf));

        while (ucx_pipe_size(request_pipe) < 1);
		_delay_ms(2);
	    ucx_pipe_read(request_pipe, message, ucx_pipe_size(request_pipe));
		printf("XTEA DRIVER :: request received %s\n", message);

		str = strtok(message, " ");
		if(strcmp(str, "enc")==0) {
			printf("XTEA DRIVER :: encrypting...\n");
			str = strtok(NULL, " ");
			hextoascii(message, str);
			//encrypt_cbc(message, enc_res_buf);
			encrypt_ecb(message, enc_res_buf);
			printf("ecb enc: %s\n", message);
			printf("XTEA DRIVER :: writing to res pipe\n");
			//ucx_task_suspend(1);
			ucx_pipe_write(result_pipe, enc_res_buf, strlen(enc_res_buf));
			//ucx_task_resume(1);
			
		}else if(strcmp(str, "dec")==0) {
			printf("XTEA DRIVER :: decrypting...\n");
			str = strtok(NULL, " ");
			hextoascii(message, str);
			decrypt_ecb(message, dec_res_buf);
			printf("ecb dec: %s\n", message);
			//decrypt_cbc(message, dec_res_buf);
			//ucx_task_suspend(1);
			printf("XTEA DRIVER :: writing to res pipe\n");
			ucx_pipe_write(result_pipe, dec_res_buf, strlen(dec_res_buf));
			//ucx_task_resume(1);

		}
    }
}

void task0(void)
{
    char message[] = "the quick brown fox jumps over the lazy dog";
	char message1[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
	char *decryptedMessage = (char *)malloc(200);
	char *encryptedMessage = (char *)malloc(200);
	char *resInAscii = (char *)malloc(200);
	char *dec_request = (char *)malloc(200);
	char *hexifiedMsgAux = (char *)malloc(200);
	char *hexifiedMsg = (char *)malloc(200);
	char *decInAscii = (char *)malloc(200);
	while (1) {
		/* write pipe - write size must be less than buffer size */
		printf("TASK 0 :: message to encrypt: %s\n", message);
		string2hexString(message, hexifiedMsgAux);
		sprintf(hexifiedMsg,"enc ");
		strcat(hexifiedMsg, hexifiedMsgAux);
		strcat(hexifiedMsg, " end");
		printf("TASK 0 :: pipe write %s\n", hexifiedMsg);
		ucx_pipe_write(request_pipe, hexifiedMsg, strlen(hexifiedMsg));
		
		//for (;;);
        while (ucx_pipe_size(result_pipe) < 1);
		_delay_ms(2);
	    ucx_pipe_read(result_pipe, encryptedMessage, ucx_pipe_size(result_pipe));
		printf("TASK 0 :: pipe read %s\n", encryptedMessage);

		encryptedMessage = strtok(encryptedMessage, " ");
		encryptedMessage = strtok(NULL, " ");

		hextoascii(resInAscii, encryptedMessage);

		//printf("Resultado em ascii: %s\n", resInAscii);
		sprintf(dec_request,"dec ");
		strcat(dec_request, encryptedMessage);
		strcat(dec_request, " end");

		printf("TASK 0 :: pipe write %s\n", dec_request);

		ucx_pipe_write(request_pipe, dec_request, strlen(dec_request));

		while (ucx_pipe_size(result_pipe) < 1);
		_delay_ms(2);

	    ucx_pipe_read(result_pipe, decryptedMessage, ucx_pipe_size(result_pipe));
		printf("TASK 0 :: pipe read %s\n", encryptedMessage);


		decryptedMessage = strtok(decryptedMessage, " ");
		decryptedMessage = strtok(NULL, " ");
		hextoascii(decInAscii, decryptedMessage);
		printf("TASK 0 :: decrypted message: %s\n", decInAscii);
		//free(hexifiedMsg);
		//free(hexifiedMsgAux);
		//free(encryptedMessage);
	}
}

void encrypt_hw(uint32_t msg[2], uint32_t xtea_key[4])
{
	XTEA_KEY0 = xtea_key[0];
	XTEA_KEY1 = xtea_key[1];
	XTEA_KEY2 = xtea_key[2];
	XTEA_KEY3 = xtea_key[3];
	XTEA_CONTROL = XTEA_ENCRYPT;

	XTEA_IN0 = msg[0];
	XTEA_IN1 = msg[1];
	XTEA_CONTROL |= XTEA_START;
	while (!(XTEA_CONTROL & XTEA_READY));
	XTEA_CONTROL &= ~XTEA_START;

	msg[0] = XTEA_OUT0;
	msg[1] = XTEA_OUT1;
}

void decrypt_hw(uint32_t msg[2], uint32_t xtea_key[4])
{

	XTEA_KEY0 = xtea_key[0];
	XTEA_KEY1 = xtea_key[1];
	XTEA_KEY2 = xtea_key[2];
	XTEA_KEY3 = xtea_key[3];

	XTEA_CONTROL = XTEA_DECRYPT;

	XTEA_IN0 = msg[0];
	XTEA_IN1 = msg[1];
	XTEA_CONTROL |= XTEA_START;
	while (!(XTEA_CONTROL & XTEA_READY));
	XTEA_CONTROL &= ~XTEA_START;

	msg[0] = XTEA_OUT0;
	msg[1] = XTEA_OUT1;
}

void encrypt_ecb(uint8_t *message, uint8_t *enc_msg_out)
{
	char *msgCopy = (char *)malloc(sizeof(message));
	strcpy(msgCopy, message);
	uint32_t xtea_key[4] = {0xf0e1d2c3, 0xb4a59687, 0x78695a4b, 0x3c2d1e0f};
	int32_t i;
	
	for (i = 0; i < 8; i++){
	 	encrypt_hw((uint32_t *)(msgCopy + i * 8), xtea_key);
	
	}
	string2hexString(msgCopy, message); //encrypted to hex
	sprintf(enc_msg_out,"res "); //add response tokens
	strcat(enc_msg_out, message);
	strcat(enc_msg_out, " end");
	//printf("ecb usando hw enc: %s\n", enc_msg_out);
	free(msgCopy);
}

void decrypt_ecb(uint8_t *enc_msg_in, uint8_t *dec_msg_out)
{
	char *msgCopy = (char *)malloc(sizeof(enc_msg_in));
	strcpy(msgCopy, enc_msg_in);

	uint32_t xtea_key[4] = {0xf0e1d2c3, 0xb4a59687, 0x78695a4b, 0x3c2d1e0f};
	int32_t i;
	for (i = 0; i < 8; i++){
		decrypt_hw((uint32_t *)(msgCopy + i * 8), xtea_key);
	}
	string2hexString(msgCopy, enc_msg_in); //encrypted to hex
	sprintf(dec_msg_out,"res "); //add response tokens
	strcat(dec_msg_out, enc_msg_in);
	strcat(dec_msg_out, " end");
	//printf("ecb usando hw dec: %s\n", dec_msg_out);
	free(msgCopy);
	
}

void decrypt_cbc(char *encrypted_msg_in, char *decrypted_msg_out)
{
	char aux[128];
	strcpy(aux, encrypted_msg_in);
	uint32_t xtea_key[4] = {0xf0e1d2c3, 0xb4a59687, 0x78695a4b, 0x3c2d1e0f};
	uint32_t iv[2] = {0x11223344, 0x55667788};
    xtea_cbc_decrypt(aux, encrypted_msg_in, strlen(encrypted_msg_in), xtea_key, iv);
	//printf("decrypt result: %s\n", aux);
	string2hexString(aux, encrypted_msg_in); //encrypted to hex
	sprintf(decrypted_msg_out,"res "); //add response tokens
	strcat(decrypted_msg_out, encrypted_msg_in);
	strcat(decrypted_msg_out, " end");
	//printf("dencrypt func: %d\n", decrypted_msg_out);
}

void encrypt_cbc(char *msg, char *enc_msg)
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
	ucx_task_add(req_handler, DEFAULT_STACK_SIZE*2);
	ucx_task_add(task0, DEFAULT_STACK_SIZE*2);

	request_pipe = ucx_pipe_create(256);		/* pipe buffer, 128 bytes (allocated on the heap) */
	decrypt_pipe = ucx_pipe_create(256);		/* pipe buffer, 64 bytes */
	result_pipe = ucx_pipe_create(256);
	// start UCX/OS, preemptive mode
	return 1;
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
		encrypt_hw(block, key);
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
		encrypt_hw(block, key);
		//xtea_encrypt(block, key, 32);
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
		//xtea_decrypt(block, key, 32);
		decrypt_hw(block, key);
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
		decrypt_hw(block, key);
		//xtea_decrypt(block, key, 32);
		block[0] ^= tiv[0];
		block[1] ^= tiv[1];
		memcpy(out, (char *)block, BLOCKLEN - rem);
	}
}

