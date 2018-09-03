//
// Created by ChileungL on 23/05/2018.
// Update by Tuber on 03/09/2018.
//

/* 接口内容编解码
 *
 * 通信内容用了个令人excited的方式进行编码，预先打一个足够大的表即可解决。只开了2048字节，够用了。
 * 需要编解码的时候把通信内容与下面这个大大的东西逐个xor，即可得到加密或解密的结果。
 */

#include "md5.h"
#include "codec.h"

void rc4_crypt(unsigned char *data, int data_len, unsigned char *key, int key_len)
{
	int i, j, k;
	unsigned char a, b, s[256];

	for (i = 0; i < 256; i++){
		s[i] = i;
	}

	for (i = j = k = 0; i < 256; i++){
		a = s[i];
		j = (j + a + key[k]) % 256;
		s[i] = s[j];
		s[j] = a;
		if (++k >= key_len) k = 0;
	}

	for (i = j = k = 0; i < data_len; i++){
		j = (j + 1) % 256;
		a = s[j];
		k = (k + a) % 256;
		s[j] = b = s[k];
		s[k] = a;
		data[i] ^= s[(a + b) % 256];
	}
}

//hardcode rc4 key
unsigned char key[] = "OKk9~Owkj#:9xZ3pHFjtg|o8hBfL~ykM";

void fuck(u_char *data, size_t len) {
	//change here by tuber
	rc4_crypt((unsigned char *)data, len, key, 32);
}

void bin2hex(char *hex, const u_char *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++)
        sprintf(hex + (i << 1), "%02X", bin[i]);
}

void hex2bin(u_char *bin, const char *hex) {
    for (size_t i = 0; hex[i << 1] && hex[i << 1 | 1]; i++)
        sscanf(hex + (i << 1), "%02X", bin + i);
}

void payload_encode(char *data, char *md5_hex, const u_char *buf) {
    size_t buf_len = strlen((const char *) buf);
    fuck((u_char *) buf, buf_len);
    bin2hex(data, buf, buf_len);

    char md5_bin[HASHSIZE] = {0};
    md5(data, (buf_len << 1), md5_bin);
    bin2hex(md5_hex, (const u_char *) md5_bin, sizeof(md5_bin));
}

void payload_decode(u_char *data, const u_char *buf, size_t buf_len) {
    hex2bin(data, (const char *) buf);
    fuck(data, buf_len >> 1);
}
