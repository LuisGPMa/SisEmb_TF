#include <ucx.h>

void xtea_encrypt(uint32_t v[2], const uint32_t key[4], uint32_t num_rounds);
void xtea_decrypt(uint32_t v[2], const uint32_t key[4], uint32_t num_rounds);
void xtea_cbc_encrypt(uint8_t *out, uint8_t *in, uint32_t len, const uint32_t key[4], const uint32_t iv[2]);
void xtea_cbc_decrypt(uint8_t *out, uint8_t *in, uint32_t len, const uint32_t key[4], const uint32_t iv[2]);
void build_enc_request(char* msg, char*buf);
void build_dec_request(char* msg, char*buf);
void build_res_request(char* msg, char*buf);

struct pipe_s *encrypt_pipe, *decrypt_pipe, *result_pipe;

void encrypt()
{
	uint8_t message[128];

    for (;;) {
        memset(message, 0, sizeof(message));
        while (ucx_pipe_size(encrypt_pipe) < 1);

	    ucx_pipe_read(encrypt_pipe, message, ucx_pipe_size(encrypt_pipe));
		hextostr(message, message);
	    printf("message: %s\n", message);

	    uint32_t xtea_key[4] = {0xf0e1d2c3, 0xb4a59687, 0x78695a4b, 0x3c2d1e0f};
	    uint32_t iv[2] = {0x11223344, 0x55667788};
		
        xtea_cbc_encrypt(message, message, sizeof(message), xtea_key, iv);
	    //printf("\nencoded message (CBC mode): %s\n", message);
		string2hexString(message, message);
		char *aux = (char *)malloc(sizeof(message) + 10);
		sprintf(aux,"res ");
		strcat(aux, message);
		strcat(aux, " end");
		ucx_pipe_write(result_pipe, message, strlen(message));
		free(aux);
		free(message);
	    //xtea_cbc_decrypt(message, message, sizeof(message), xtea_key, iv);
	    //printf("\ndecoded message (CBC mode): %s\n", message);
		

    }

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

void task0(void)
{
    char message[] = "the quick brown fox jumps over the lazy dog";
	char encryptedMessage = (char *)malloc(sizeof(message)*2 + 10);
	while (1) {
		/* write pipe - write size must be less than buffer size */
		char *hexifiedMsgAux = (char *)malloc(sizeof(message)*2 + 10);
		string2hexString(message, hexifiedMsgAux);
		char *hexifiedMsg = (char *)malloc(sizeof(message)*2 + 10);
		sprintf(hexifiedMsg,"enc ");
		strcat(hexifiedMsg, hexifiedMsgAux);
		strcat(hexifiedMsg, " end");
		ucx_pipe_write(encrypt_pipe, hexifiedMsg, strlen(hexifiedMsg));
	    ucx_pipe_read(result_pipe, encryptedMessage, ucx_pipe_size(result_pipe));
		printf("resultado: %s", encryptedMessage);
		free(hexifiedMsg);
		free(hexifiedMsgAux);
		


		//printf("original message: %s\n", message);
		//char *hex = (char *)malloc(sizeof(message)*2);
		//printf("%08x malloc()\n", hex);
		//string2hexString(message, hex);
		//printf("hexified: %s\n", hex);
		//char *backToASCII = (char *)malloc(sizeof(message));
		//hextostr(backToASCII, hex);
		//printf("back to ascii: %s\n", backToASCII);
		//free(hex);
		//free(hexifiedMsg);
		//free(enc);
		//free(backToASCII);
	}
}

int32_t app_main(void)
{
	ucx_task_add(encrypt, DEFAULT_STACK_SIZE);
	ucx_task_add(task0, DEFAULT_STACK_SIZE);

	encrypt_pipe = ucx_pipe_create(128);		/* pipe buffer, 128 bytes (allocated on the heap) */
	decrypt_pipe = ucx_pipe_create(128);		/* pipe buffer, 64 bytes */
	result_pipe = ucx_pipe_create(128);
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
