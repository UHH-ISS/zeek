
%extern{
#include <vector>
#include <algorithm>
#include <iostream>
#include <iterator>

#include "util.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "file_analysis/Manager.h"

#include "tls-handshake_pac.h"

#define MSB(a) ((a>>8)&0xff)
#define LSB(a) (a&0xff)

typedef struct Data_ {
		uint8_t *data;
		int len;
} Data;

static int fmt_seq(uint32_t num, uint8_t * buf)
	{
	uint32_t netnum;

	memset(buf,0,8);
	netnum=htonl(num);
	memcpy(buf+4,&netnum,4);

	return(0);
	}

static int r_data_destroy(Data ** dp)
	{
	if(!dp || !*dp)
		return(0);

	if((*dp)->data)
		free((*dp)->data);

	free(*dp);
	*dp=0;

	return(0);
	}

static int r_data_create(Data ** dp, uint8_t * d, int l)
	{
	Data *d_=0;
	int _status;

	if(!(d_=(Data *)calloc(sizeof(Data),1)))
		exit(1);
	if(!(d_->data=(uint8_t *)malloc(l)))
		exit(1);

	memcpy(d_->data,d,l);
	d_->len=l;

	*dp=d_;

	_status=0;
	abort:
	if(_status)
		r_data_destroy(&d_);

	return(_status);
	}

static int r_data_alloc(Data ** dp, int l)
	{
	Data *d_=0;
	int _status;

	if(!(d_=(Data *)calloc(sizeof(Data),1)))
		exit(1);
	if(!(d_->data=(uint8_t *)calloc(l,1)))
		exit(1);

	d_->len=l;

	*dp=d_;
	_status=0;

	abort:
	if(_status)
		r_data_destroy(&d_);

	return(_status);
	}

static int tls_P_hash(Data * secret,Data * seed, const EVP_MD * md, Data * out)
	{
	uint8_t *ptr=out->data;
	int left=out->len;
	int tocpy;
	uint8_t *A;
	uint8_t _A[128],tmp[128];
	unsigned int A_l,tmp_l;
	HMAC_CTX *hm = HMAC_CTX_new();

	//CRDUMPD("P_hash secret",secret);
	//CRDUMPD("P_hash seed",seed);

	A=seed->data;
	A_l=seed->len;

	while(left)
		{
		HMAC_Init(hm,secret->data,secret->len,md);
		HMAC_Update(hm,A,A_l);
		HMAC_Final(hm,_A,&A_l);
		A=_A;

		HMAC_Init(hm,secret->data,secret->len,md);
		HMAC_Update(hm,A,A_l);
		HMAC_Update(hm,seed->data,seed->len);
		HMAC_Final(hm,tmp,&tmp_l);

		tocpy=MIN(left,tmp_l);
		memcpy(ptr,tmp,tocpy);
		ptr+=tocpy;
		left-=tocpy;
		}

	HMAC_CTX_free(hm);
	//CRDUMPD("P_hash out",out);

	return (0);
	}

static int tls12_prf(Data *secret, char *usage, Data *rnd1, Data *rnd2, Data *out)
	{
	const EVP_MD *md;
	int r,_status;
	Data *sha_out=0;
	Data *seed;
	uint8_t *ptr;
	int i, j, dgi;

	r=r_data_alloc(&sha_out,MAX(out->len,64)); /* assume max SHA512 */
	if(r)
		exit(1);
	r=r_data_alloc(&seed,strlen(usage)+rnd1->len+rnd2->len);
	if(r)
		exit(1);
	ptr=seed->data;
	memcpy(ptr,usage,strlen(usage)); ptr+=strlen(usage);
	memcpy(ptr,rnd1->data,rnd1->len); ptr+=rnd1->len;
	memcpy(ptr,rnd2->data,rnd2->len); ptr+=rnd2->len;

	/* Earlier versions of openssl didn't have SHA384 of course... */
	if ((md=EVP_get_digestbyname("SHA384")) == NULL) {
		return(1);
	}
	//printf("Digest name is %s\n", "SHA384");
	r = tls_P_hash(secret,seed,md,sha_out);
	if(r)
		exit(1);

	for(i=0;i<out->len;i++)
		out->data[i]=sha_out->data[i];

	// CRDUMPD("PRF out",out);
	_status=0;
	abort:
	r_data_destroy(&sha_out);
	r_data_destroy(&seed);
	return(_status);
	}

static void print_hex(string name, uint8_t * data, int len)
	{
	int i = 0;
	printf("%s (%d): ", name.c_str(), len);
	if (len > 0)
		printf("0x%02x", data[0]);

	for (i = 1; i < len; i++)
		{
		printf(" 0x%02x", data[i]);
		}
	printf("\n");
	}
%}


refine connection SSL_Conn += {

	%member{
		int established_;
	%}

	%init{
		established_ = false;
	%}

	%cleanup{
	%}

	function setEstablished() : bool
		%{
		established_ = true;
		return true;
		%}

	function proc_alert(rec: SSLRecord, level : int, desc : int) : bool
		%{
		if ( ssl_alert )
			zeek::BifEvent::enqueue_ssl_alert(bro_analyzer(), bro_analyzer()->Conn(),
							${rec.is_orig}, level, desc);
		return true;
		%}
	function proc_unknown_record(rec: SSLRecord) : bool
		%{
		bro_analyzer()->ProtocolViolation(fmt("unknown SSL record type (%d) from %s",
				${rec.content_type},
				orig_label(${rec.is_orig}).c_str()));
		return true;
		%}

	function parse_application_tls_data(tlshdr: bytestring, is_orig: bool, content_type: uint8, raw_tls_version: uint16) : bool
		%{
		unsigned char* nexthdr {nullptr};
		uint16_t nexthdr_size {0};

		uint8_t CR[32] = {0x00};

		uint8_t c_wk[32];
		uint8_t s_wk[32];
		uint8_t c_iv[4];
		uint8_t s_iv[4];

		uint8_t s_aead_nonce[12];
		uint8_t s_aead_tag[13];

		Data *masterkey;
		Data *srand;
		Data *crand;
		Data *out;

		EVP_CIPHER_CTX *ctx;
		int decrl = 0;
		int res;

		// Unsupported cipher suite. Currently supported:
		// - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 == 0xC030
		auto cipher = bro_analyzer()->handshake()->chosen_cipher();
		if (cipher != 0xC030)
			{
			//printf("unsupported cipher suite: %d\n", cipher);
			return false;
			}

		auto secret = bro_analyzer()->secret();

		// Neither secret or key present: abort
		if (secret->Len() == 0 && bro_analyzer()->keys()->Len() == 0)
			{
			printf("Could not decrypt packet (missing key):\n");
			print_hex("->client_random:", bro_analyzer()->handshake()->client_random().data(), bro_analyzer()->handshake()->client_random().length());
			return false;
			}

		// Secret present, but no keys derived yet: derive keys
		if (secret->Len() != 0 && bro_analyzer()->keys()->Len() == 0)
			{
			uint32_t gmt_unix_time = htonl((uint32_t) bro_analyzer()->handshake()->gmt_unix_time());
			memcpy(CR, &(gmt_unix_time), 4);
			memcpy(CR + 4, bro_analyzer()->handshake()->client_random().data(), bro_analyzer()->handshake()->client_random().length());
			r_data_create(&masterkey, (uint8_t *) secret->Bytes(), secret->Len());
			r_data_create(&srand, bro_analyzer()->handshake()->server_random().data(), bro_analyzer()->handshake()->server_random().length());
			r_data_create(&crand, CR, 32);
			r_data_alloc(&out, 72);

            // TLS PRF
			tls12_prf(masterkey, "key expansion", srand, crand, out);

			// Save keys
			bro_analyzer()->SetKeys(out->data, 72);

			r_data_destroy(&masterkey);
			r_data_destroy(&srand);
			r_data_destroy(&crand);
			r_data_destroy(&out);
		}

		auto keys = bro_analyzer()->keys();
		if (keys->Len() != 0)
			{
			// extract keys from variable
			memcpy(c_wk, keys->Bytes(), 32);
			memcpy(s_wk, &(keys->Bytes()[32]), 32);
			memcpy(c_iv, &(keys->Bytes()[64]), 4);
			memcpy(s_iv, &(keys->Bytes()[68]), 4);

			//unsigned char decr [400000] = {0x00};
			unsigned char *decr; // [400000] = {0x00};

			nexthdr = tlshdr.data();
			nexthdr_size = tlshdr.length();

			if (is_orig)
				c_seq_++;
			else
				s_seq_++;

			//printf("nexthdr_size is %u\n", nexthdr_size);
			decr = (unsigned char*) malloc(nexthdr_size);
			//print_hex("nexthdr", (uint8_t*) nexthdr, nexthdr_size);

			if (is_orig)
				memcpy(s_aead_nonce, c_iv, 4);
			else
				memcpy(s_aead_nonce, s_iv, 4);
			memcpy(&(s_aead_nonce[4]), nexthdr, 8);

			ctx = EVP_CIPHER_CTX_new();
			EVP_CIPHER_CTX_init(ctx);
			EVP_CipherInit(ctx, EVP_aes_256_gcm(), NULL, NULL, 0);

			nexthdr = nexthdr + 8;
			nexthdr_size -= 8;
			nexthdr_size -= 16;

			if (is_orig)
				EVP_DecryptInit(ctx, EVP_aes_256_gcm(), c_wk, s_aead_nonce);
			else
				EVP_DecryptInit(ctx, EVP_aes_256_gcm(), s_wk, s_aead_nonce);
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, nexthdr + nexthdr_size);

			if (is_orig)
				fmt_seq(c_seq_, s_aead_tag);
			else
				fmt_seq(s_seq_, s_aead_tag);

			s_aead_tag[8] = content_type;
			s_aead_tag[9] = MSB(raw_tls_version);
			s_aead_tag[10] = LSB(raw_tls_version);
			s_aead_tag[11] = MSB(nexthdr_size);
			s_aead_tag[12] = LSB(nexthdr_size);
			//print_hex("AEAD TAG", s_aead_tag, 13);

			EVP_DecryptUpdate(ctx, NULL, &decrl, s_aead_tag, 13);
			EVP_DecryptUpdate(ctx, decr, &decrl, (const unsigned char*) nexthdr, nexthdr_size);

			if (!(res = EVP_DecryptFinal(ctx, NULL, &res)))
				{
				printf("Decryption failed with return code %d. Invalid key?\n", res);
				free(decr);
				return false;
				}

			EVP_CIPHER_CTX_free(ctx);
			bro_analyzer()->ForwardHTTPData(decrl, reinterpret_cast<const u_char*>(decr), is_orig);

			free(decr);
			return true;
		}

		// This is only reached if key derivation somehow failed
		return false;
		%}

	function proc_ciphertext_record(rec : SSLRecord, cont: bytestring) : bool
		%{
		if ( client_state_ == STATE_ENCRYPTED &&
			server_state_ == STATE_ENCRYPTED &&
			established_ == false )
			{
			established_ = true;
			if ( ssl_established )
				zeek::BifEvent::enqueue_ssl_established(bro_analyzer(), bro_analyzer()->Conn());
			}

		if ( ssl_encrypted_data )
			{
			zeek::BifEvent::enqueue_ssl_encrypted_data(bro_analyzer(),
				bro_analyzer()->Conn(), ${rec.is_orig}, ${rec.raw_tls_version}, ${rec.content_type}, ${rec.length},
				zeek::make_intrusive<zeek::StringVal>(cont.length(), (const char*) cont.data()));
			if (rec->content_type() == APPLICATION_DATA)
				{
				parse_application_tls_data(cont, rec->is_orig(), rec->content_type(), rec->raw_tls_version());
				}
			}
		return true;
		%}

	function proc_plaintext_record(rec : SSLRecord) : bool
		%{
		if ( ssl_plaintext_data )
			zeek::BifEvent::enqueue_ssl_plaintext_data(bro_analyzer(),
				bro_analyzer()->Conn(), ${rec.is_orig}, ${rec.raw_tls_version}, ${rec.content_type}, ${rec.length});

		return true;
		%}

	function proc_heartbeat(rec : SSLRecord, type: uint8, payload_length: uint16, data: bytestring) : bool
		%{
		if ( ssl_heartbeat )
			zeek::BifEvent::enqueue_ssl_heartbeat(bro_analyzer(),
				bro_analyzer()->Conn(), ${rec.is_orig}, ${rec.length}, type, payload_length,
				zeek::make_intrusive<zeek::StringVal>(data.length(), (const char*) data.data()));
		return true;
		%}

	function proc_check_v2_server_hello_version(version: uint16) : bool
		%{
		if ( version != SSLv20 )
			{
			bro_analyzer()->ProtocolViolation(fmt("Invalid version in SSL server hello. Version: %d", version));
			bro_analyzer()->SetSkip(true);
			return false;
			}

		return true;
		%}


	function proc_ccs(rec: SSLRecord) : bool
		%{
		if ( ssl_change_cipher_spec )
			zeek::BifEvent::enqueue_ssl_change_cipher_spec(bro_analyzer(),
				bro_analyzer()->Conn(), ${rec.is_orig});

		return true;
		%}

};

refine typeattr Alert += &let {
	proc : bool = $context.connection.proc_alert(rec, level, description);
};

refine typeattr Heartbeat += &let {
	proc : bool = $context.connection.proc_heartbeat(rec, type, payload_length, data);
};

refine typeattr UnknownRecord += &let {
	proc : bool = $context.connection.proc_unknown_record(rec);
};

refine typeattr CiphertextRecord += &let {
	proc : bool = $context.connection.proc_ciphertext_record(rec, cont);
}

refine typeattr PlaintextRecord += &let {
	proc : bool = $context.connection.proc_plaintext_record(rec);
}

refine typeattr ChangeCipherSpec += &let {
	proc : bool = $context.connection.proc_ccs(rec);
};
