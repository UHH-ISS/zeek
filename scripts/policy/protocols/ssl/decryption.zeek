#! Decrypt SSL/TLS payloads

@load base/frameworks/input
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/ssl

module SSL;

# Local
const input_stream_name = "input-tls-keylog-file";
global input_done = F;

type Idx: record {
	client_random: string;
};

type Val: record {
	secret: string;
};

global randoms: table[string] of string = {};

# Export
export {
	const cipher_groups: table[string] of string = {
		["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"] = "GALOIS_SHA384"
	} &redef;

	const keylog_file = getenv("ZEEK_TLS_KEYLOG_FILE") &redef;

	const keylog_listen = getenv("ZEEK_TLS_KEYLOG_LISTEN") &redef;

	global secrets: table[string] of string = {} &redef;

	event SSL::add_secret(client_random: string, secret: string) {
		SSL::secrets[client_random] = secret;
	}
}

# Events for decryption
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
	# save random as it is not present in ssl_encrypted_data
	# FIXME: the client random could be attached to Conn::Info
	randoms[c$uid] = client_random;

	if (client_random in secrets) {
		#print "setting secret", randoms[c$uid], secrets[randoms[c$uid]];
		set_secret(c, secrets[client_random]);
	}
}

event ssl_encrypted_data(c: connection, is_orig: bool, record_version: count, content_type: count, length: count, payload: string) {
	if (c$uid in randoms) {
		if (randoms[c$uid] in secrets) {
			#print "setting secret", randoms[c$uid], secrets[randoms[c$uid]];
			set_secret(c, secrets[randoms[c$uid]]);
		}
		else {
			print "No suitable key found for random:", randoms[c$uid];
		}
	}
}

event SSL::tls_input_done() {
	#print "initialized secrets", secrets;
	continue_processing();
}

event Input::end_of_data(name: string, source: string) {
	if (name == input_stream_name) {
		event SSL::tls_input_done();
	}
}

event zeek_init() {
	print "policy/protocols/ssl/decryption: zeek_init()";
	# ingest keylog file if the environment is set
	if (keylog_file != "") {
		suspend_processing();

		Input::add_table([$name=input_stream_name, $source=keylog_file, $destination=secrets, $idx=Idx, $val=Val, $want_record=F]);
		Input::remove(input_stream_name);
	} else if (keylog_listen != "") {
		suspend_processing();

		Broker::listen("0.0.0.0", 9999/tcp, 1sec);
		Broker::subscribe("/zeek/tls/secret");
	}
}
