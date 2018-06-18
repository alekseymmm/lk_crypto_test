/*
 * rdx_crypto.c
 *
 *  Created on: 30 may 2018.
 *      Author: alekseym
 */
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <crypto/akcipher.h>

#include "rdx_crypto.h"

#define  KEY_LEN 128
unsigned  char *priv_key =
		"\x30\x82\x02\x5C\x02\x01\x00\x02\x81\x81\x00\xCA\xA3\x2B\x5A\xDB"
		"\xAC\xBB\xE1\xFF\x5E\x13\x42\x30\x21\x84\xE2\xF6\x5D\x99\xE5\x8A"
		"\x48\x05\xCB\x93\xDA\x1E\x29\x60\xC0\xDF\x33\xF0\xC2\x8C\xD4\x70"
		"\x83\xD4\x10\x17\x39\x22\x1C\x81\xDF\x47\x83\x7D\xB8\xEA\xAA\xEC"
		"\xCD\x93\xBE\x90\xB0\x50\xAC\xD5\x6A\x8C\x34\xC6\xFC\xA5\xFA\x03"
		"\x2C\x12\x7A\xA5\x2B\x09\xE9\xBF\x84\x98\xFA\x8B\xFC\xF9\xEA\xAE"
		"\x15\x52\x3D\xBE\x47\x38\x3E\x07\x26\xB0\x8A\x09\x1E\xA0\x95\x80"
		"\x80\xC4\x6F\xD9\x68\xE8\x59\xC4\xBE\xCC\xE6\x97\xF5\x9E\x4A\x06"
		"\x23\x3B\x23\x11\xC4\x12\xFB\x6A\x33\xB6\xCF\x02\x03\x01\x00\x01"
		"\x02\x81\x80\x61\xDD\x09\xDC\x38\x89\xA4\xB7\x91\xE0\x3A\x46\xD5"
		"\xFD\xEA\x32\xBE\xAF\x17\xDB\x2E\xBC\x77\xE8\x08\xC0\xE7\x9E\x2E"
		"\x37\x17\xD4\xFA\xEA\xCA\x9E\xF2\xB4\x08\x1F\xB9\x47\x83\x7C\xE7"
		"\x10\x11\x76\xA4\xAA\x40\xD3\x49\xC8\x43\x19\x5E\xC1\x78\x44\xF0"
		"\x51\x23\xE2\xA0\x2B\x1D\xD0\x60\x97\x96\x2F\x0A\x73\xEA\xAD\xB8"
		"\x9A\xB6\x18\x27\x6E\xC6\x52\x10\xCC\x64\xC7\x8C\xC0\x2C\xD2\xCD"
		"\xAF\x56\x2E\x35\x14\xA9\x05\xEF\xB0\x47\x51\xE5\x0F\x6A\xDC\x4E"
		"\xA0\x2F\xC8\xC3\x12\x26\xA6\x6C\xDC\x7C\xB6\xF4\xBC\x34\x93\x60"
		"\x0C\x7F\xE9\x02\x41\x00\xFC\x62\xD1\x5A\xD5\x62\xEB\xC9\x89\x45"
		"\x64\xCA\x3B\x42\x55\xCE\xCC\x89\x9F\x5C\x0E\x1E\x76\x78\x0F\x83"
		"\x37\x8A\xA2\x8F\x03\x77\xE3\xAA\x6F\x0C\x03\xC3\xB6\xB1\xC0\x6F"
		"\xCD\xB6\x71\xC8\x87\xAB\x8D\x37\x4A\x6A\x6C\x1D\xCF\xC1\x59\x08"
		"\x8F\xC6\xF1\x25\x18\x8B\x02\x41\x00\xCD\x89\xFC\x63\x35\xA5\xD4"
		"\xEC\x4B\x19\xA6\xB1\xF5\xA2\xCA\x1F\xB1\x31\x10\x93\x56\xDE\x0E"
		"\x2B\x99\x13\x45\x49\xF9\xA4\x13\x8D\x5E\x3B\xF4\x90\x33\xEB\x28"
		"\x0B\x45\xAE\xA2\xF3\x6A\xEE\x74\x33\x05\x06\x9B\x2C\xA9\x78\x69"
		"\xBA\x67\xBC\x5E\x0B\x04\x07\x9F\x4D\x02\x41\x00\xC6\x97\x3B\x04"
		"\xAE\x43\x58\x25\x0C\xCE\x7D\xB0\x63\x50\x9F\x14\x49\xFD\x40\x57"
		"\xBF\x04\x59\x53\xBF\x61\x10\xA3\x15\xA6\x52\xA4\x53\x90\x18\x30"
		"\xEC\x05\x64\x0C\x19\xCF\xDF\x9E\x5F\x89\xDA\xB7\x32\x36\xFF\x67"
		"\x1E\x0B\x97\x1E\x1C\x60\x90\x41\x8A\x1E\x16\x61\x02\x40\x71\x24"
		"\x80\x16\x6C\xB5\xB8\x9B\xCA\x4B\x78\x83\x85\xDF\xF2\xBB\xB7\x62"
		"\x76\xE9\x64\x6C\x20\x08\xC7\xDE\xDF\xC9\x74\xEE\x69\x04\xEC\xD6"
		"\xBC\x2D\x95\x26\xE1\x88\x32\xF7\x8B\x23\xCB\xBD\x2F\xA1\xD6\x26"
		"\x68\xCD\x11\x0D\x03\xC6\x64\xCC\x40\x48\x78\x13\x6A\x11\x02\x40"
		"\x7F\xF6\xF5\xAF\xEB\xCA\x8A\x52\xE0\x2B\xA9\xA4\x56\x6B\xC3\x1F"
		"\x71\x0E\xBE\x5E\xF5\xB0\x10\x3F\x40\x18\x20\xB9\xFC\xC2\xF2\x22"
		"\x4B\x55\x4A\x05\x4C\x44\xD6\x43\x44\xD4\x9D\x61\xB1\x12\x98\x4E"
		"\xE6\x1D\xA5\xFE\x73\xEC\x6E\x7B\x53\xF3\x1A\x5C\x56\x7E\x44\x41";

int priv_key_len = 608	;

unsigned char *pub_key =
		"\x30\x81\x89\x02\x81\x81\x00\xCA\xA3\x2B\x5A\xDB\xAC\xBB\xE1\xFF"
		"\x5E\x13\x42\x30\x21\x84\xE2\xF6\x5D\x99\xE5\x8A\x48\x05\xCB\x93"
		"\xDA\x1E\x29\x60\xC0\xDF\x33\xF0\xC2\x8C\xD4\x70\x83\xD4\x10\x17"
		"\x39\x22\x1C\x81\xDF\x47\x83\x7D\xB8\xEA\xAA\xEC\xCD\x93\xBE\x90"
		"\xB0\x50\xAC\xD5\x6A\x8C\x34\xC6\xFC\xA5\xFA\x03\x2C\x12\x7A\xA5"
		"\x2B\x09\xE9\xBF\x84\x98\xFA\x8B\xFC\xF9\xEA\xAE\x15\x52\x3D\xBE"
		"\x47\x38\x3E\x07\x26\xB0\x8A\x09\x1E\xA0\x95\x80\x80\xC4\x6F\xD9"
		"\x68\xE8\x59\xC4\xBE\xCC\xE6\x97\xF5\x9E\x4A\x06\x23\x3B\x23\x11"
		"\xC4\x12\xFB\x6A\x33\xB6\xCF\x02\x03\x01\x00\x01";

int pub_key_len = 140;

static void hexdump(unsigned char *buf,unsigned int len)
{
	int i;

	for (i = 0; i < len; i++) {
		pr_warn(KERN_CONT "%02X", buf[i]);
	}
	pr_warn("\n");
}


static int __rdx_akcrypto_tfm(struct crypto_akcipher *tfm,
			void *input, int len, void *output, int phase)
{
	struct akcipher_request *req;
	void *out_buf = NULL;
//	struct tcrypt_result result;
	unsigned int out_len_max = 0;
	struct scatterlist src, dst;
	void *xbuf = NULL;
	int err = 0;

	xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!xbuf)
		return err;

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto free_xbuf;

//	init_completion(&result.completion);

	if (phase) {
		pr_warn("set pub key \n");
		err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
	} else {
		pr_warn("set priv key\n");
		//err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
		err = crypto_akcipher_set_priv_key(tfm, priv_key, priv_key_len);
	}

	if (err){
		printk("set key error! err: %d phase: %d\n", err,phase);
		goto free_req;
	}

	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	pr_warn("out_len_max = %d, len = %d\n", out_len_max, len);
	out_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (!out_buf)
		goto free_req;

	if (WARN_ON(len > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf, input, len);
	sg_init_one(&src, xbuf, len);
	sg_init_one(&dst, out_buf, out_len_max);
	akcipher_request_set_crypt(req, &src, &dst, len, out_len_max);
//    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
//                               tcrypt_complete, &result);

	if (phase) { //encryption phase
		//err = wait_async_op(&result, crypto_akcipher_encrypt(req));
		err =  crypto_akcipher_encrypt(req);
		if (err) {
			pr_err("alg: akcipher: encrypt test failed. err %d\n",
					err);
			goto free_all;
		}
		pr_warn("after enc in out_buf:\n");
		hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, out_len_max);
		//crypted_len = out_len_max;

	} else { //decryption phase
		//err = wait_async_op(&result, crypto_akcipher_decrypt(req));
		err = crypto_akcipher_decrypt(req);
		if (err) {
			pr_err("alg: akcipher: decrypt test failed. err %d\n",
					err);
			goto free_all;
		}
		pr_warn("after decrypt in out_buf:\n");
		hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, out_len_max);
	}

free_all:
	kfree(out_buf);
free_req:
	akcipher_request_free(req);
free_xbuf:
	kfree(xbuf);
	return err;
}

int rdx_akcrypto_enc_dec(void *input, int len, void *output, int phase)
{
     struct crypto_akcipher *tfm;
     int err = 0;

     tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
     if (IS_ERR(tfm)) {
             pr_err("alg: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
             return PTR_ERR(tfm);
     }
     err = __rdx_akcrypto_tfm(tfm, input, len, output, phase);

     crypto_free_akcipher(tfm);
     return err;
}

static int __rdx_akcrypto_tfm_sv(struct crypto_akcipher *tfm,
			void *input, int len, void *output, int phase)
{
	struct akcipher_request *req;
	void *out_buf = NULL;
//	struct tcrypt_result result;
	unsigned int out_len_max = 0;
	struct scatterlist src, dst;
	void *xbuf = NULL;
	int err = 0;

	xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!xbuf)
		return err;

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto free_xbuf;

//	init_completion(&result.completion);

	if (!phase) {
		pr_debug("set pub key \n");
		err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
	} else {
		pr_debug("set priv key\n");
		//err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
		err = crypto_akcipher_set_priv_key(tfm, priv_key, priv_key_len);
	}

	if (err){
		pr_err("set key error! err: %d phase: %d\n", err, phase);
		goto free_req;
	}

	err = -ENOMEM;
	out_len_max = crypto_akcipher_maxsize(tfm);
	pr_debug("out_len_max = %d, len = %d\n", out_len_max, len);
	out_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (!out_buf)
		goto free_req;

	if (WARN_ON(len > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf, input, len);
	sg_init_one(&src, xbuf, len);
	sg_init_one(&dst, out_buf, out_len_max);
	akcipher_request_set_crypt(req, &src, &dst, len, out_len_max);
//    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
//                               tcrypt_complete, &result);

	if (phase) { //sign phase
		//err = wait_async_op(&result, crypto_akcipher_encrypt(req));
		err =  crypto_akcipher_sign(req);
		if (err) {
			pr_err("alg: akcipher: sign failed. err %d\n", err);
			goto free_all;
		}
		pr_debug("after sign in out_buf:\n");
		//hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, out_len_max);
	} else { //verification phase
		//err = wait_async_op(&result, crypto_akcipher_decrypt(req));
		err = crypto_akcipher_verify(req);
		if (err) {
			pr_err("alg: akcipher: verify failed. err %d\n",
					err);
			goto free_all;
		}
		pr_debug("after verify in out_buf:\n");
		//hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, out_len_max);
	}

free_all:
	kfree(out_buf);
free_req:
	akcipher_request_free(req);
free_xbuf:
	kfree(xbuf);
	return err;
}

int rdx_akcrypto_sign_ver(void *input, int len, void *output, int phase)
{
     struct crypto_akcipher *tfm;
     int err = 0;

     tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
     if (IS_ERR(tfm)) {
             pr_err("alg: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
             return PTR_ERR(tfm);
     }
     err = __rdx_akcrypto_tfm_sv(tfm, input, len, output, phase);

     crypto_free_akcipher(tfm);
     return err;
}
char *msg = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
int msg_len = 8;

int rdx_crypto_test(void)
{
	int ret = 0;
	char *c, *m;
	c = kzalloc(KEY_LEN, GFP_KERNEL);
	m = kzalloc(KEY_LEN, GFP_KERNEL);

	pr_warn("initial msg :\n");
	hexdump(msg, msg_len);

	ret = rdx_akcrypto_enc_dec(msg, msg_len, c, RDX_ENCRYPT);
	if (ret) {
		pr_err ("Encryption error\n");
		goto err;
	}
	pr_warn("encrypted msg :\n");
	hexdump(c, KEY_LEN);

	ret = rdx_akcrypto_enc_dec(c, KEY_LEN, m, RDX_DECRYPT);
	if (ret) {
		pr_err ("Decryption error\n");
		goto err;
	}
	pr_warn("decrypted msg :\n");
	hexdump(m, KEY_LEN);
err:
	kfree(c);
	kfree(m);
	return ret;
}

int rdx_sign_test(void)
{
	int ret = 0;
	char *c, *m;
	c = kzalloc(KEY_LEN, GFP_KERNEL);
	m = kzalloc(KEY_LEN, GFP_KERNEL);

	pr_warn("initial msg :\n");
	hexdump(msg, msg_len);

	ret = rdx_akcrypto_sign_ver(msg, msg_len, c, RDX_RSA_SIGN);
	if (ret) {
		pr_err ("RSA sign error\n");
		goto err;
	}
	pr_warn("signed msg :\n");
	hexdump(c, KEY_LEN);

	ret = rdx_akcrypto_sign_ver(c, KEY_LEN, m, RDX_RSA_VERIFY);
	if (ret) {
		pr_err ("RSA verify error\n");
		goto err;
	}
	pr_warn("verified msg :\n");
	hexdump(m, KEY_LEN);
err:
	kfree(c);
	kfree(m);
	return ret;
}
