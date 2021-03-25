
#include "SSL.h"
#include "analyzer/Manager.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "util.h"

#include "events.bif.h"
#include "ssl_pac.h"
#include "tls-handshake_pac.h"

using namespace analyzer::ssl;

SSL_Analyzer::SSL_Analyzer(Connection* c)
: tcp::TCP_ApplicationAnalyzer("SSL", c)
	{
	interp = new binpac::SSL::SSL_Conn(this);
	handshake_interp = new binpac::TLSHandshake::Handshake_Conn(this);
	had_gap = false;
	secret_ = new zeek::StringVal(0, "");
	keys_ = new zeek::StringVal(0, "");
	pia = nullptr;
	}

SSL_Analyzer::~SSL_Analyzer()
	{
	delete interp;
	delete handshake_interp;
	delete secret_;
	delete keys_;
	}

void SSL_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	handshake_interp->FlowEOF(true);
	handshake_interp->FlowEOF(false);
	}

void SSL_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	handshake_interp->FlowEOF(is_orig);
	}

void SSL_Analyzer::StartEncryption()
	{
	interp->startEncryption(true);
	interp->startEncryption(false);
	interp->setEstablished();
	}

void SSL_Analyzer::SetSecret(const u_char* secret, int len)
	{
	secret_ = new zeek::StringVal(len, (const char *) secret);
	}

void SSL_Analyzer::SetKeys(const u_char* keys, int len)
	{
	keys_ = new zeek::StringVal(len, (const char *) keys);
	}

void SSL_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::SendHandshake(uint16_t raw_tls_version, const u_char* begin, const u_char* end, bool orig)
	{
	handshake_interp->set_record_version(raw_tls_version);
	try
		{
		handshake_interp->NewData(orig, begin, end);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void SSL_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}

void SSL_Analyzer::ForwardDecryptedData(int len, const u_char* data, bool orig)
	{
	if ( ! pia )
		{
		pia = new analyzer::pia::PIA_TCP(Conn());
		if ( AddChildAnalyzer(pia) )
			{
			pia->FirstPacket(true, nullptr);
			pia->FirstPacket(false, nullptr);
			}
		else
			reporter->FatalError("Could not initialize PIA");

		// and also statically add HTTP/H2 at the moment. We should move this bit
		// to scriptland
		auto http = analyzer_mgr->InstantiateAnalyzer("HTTP", Conn());
		if ( http )
			AddChildAnalyzer(http);
		auto http2 = analyzer_mgr->InstantiateAnalyzer("HTTP2", Conn());
		if ( http2 )
			AddChildAnalyzer(http2);
		}

	ForwardStream(len, data, orig);
	}
