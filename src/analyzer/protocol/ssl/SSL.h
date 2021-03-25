#pragma once

#include "events.bif.h"

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/pia/PIA.h"

namespace binpac { namespace SSL { class SSL_Conn; } }

namespace binpac { namespace TLSHandshake { class Handshake_Conn; } }

namespace analyzer { namespace ssl {

class SSL_Analyzer final : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit SSL_Analyzer(Connection* conn);
	~SSL_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	void SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end, bool orig);

	// Tell the analyzer that encryption has started.
	void StartEncryption();

	// Key material for decryption
	zeek::StringVal* secret() { return secret_; }
	void SetSecret(const u_char* secret, int len);

	zeek::StringVal* keys() { return keys_; }
	void SetKeys(const u_char* keys, int len);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SSL_Analyzer(conn); }

	binpac::TLSHandshake::Handshake_Conn* handshake() { return handshake_interp; }
	void ForwardDecryptedData(int len, const u_char* data, bool orig);

protected:
	binpac::SSL::SSL_Conn* interp;
	binpac::TLSHandshake::Handshake_Conn* handshake_interp;
	bool had_gap;

	zeek::StringVal* secret_;
	zeek::StringVal* keys_;
	analyzer::pia::PIA_TCP *pia;
};

} } // namespace analyzer::*
