#ifndef __SRV_H__
#define __SRV_H__

#include <sys/time.h>
#include <string>
#include <vector>
#include <cstdint>
#include <evhtp.h>
#include <univalue.h>
#include <openssl/sha.h>

#define DEFAULT_DATASTORE_FN "srv.rocks"

namespace Unisrv {

class View {
protected:
	std::string		name_;
	std::string		driver_;
	std::string		path_;
	std::string		errstr_;
public:

	View(const std::string& _name, const std::string& _driver,
	     const std::string& _path) {
		name_ = _name;
		driver_ = _driver;
		path_ = _path;
	}
	virtual ~View() {}

	const std::string& name() const { return name_; }
	const std::string& driver() const { return driver_; }
	const std::string& path() const { return path_; }
	const std::string& errstr() const { return errstr_; }
	bool err() const { return errstr_.empty(); }

	virtual bool open() = 0;
	virtual void close() = 0;
	virtual bool get(const std::string& key, std::string *val) = 0;
	virtual bool put(const std::string& key, const std::string& val) = 0;
	virtual bool del(const std::string& key) = 0;
};

class Endpoint {
public:
	std::string	name;
	std::string	urlpath;
	std::string	protocol;
	View		*view;

	bool		authReq;
	bool		wantInput;
};

} // namespace Unisrv

struct HttpApiEntry {
	bool			authReq;	// authentication req'd?

	const char		*path;
	bool			pathIsRegex;

	evhtp_callback_cb	cb;
	bool			wantInput;
	bool			jsonInput;
};

class ReqState {
public:
	std::string		body;
	SHA256_CTX		bodyHash;
	std::vector<unsigned char> md;

	std::string		path;
	struct timeval		tstamp;

	UniValue		jval;

	Unisrv::Endpoint	*endpt;
	struct HttpApiEntry	apiEnt_;
	const struct HttpApiEntry *apiEnt;

	ReqState() : md(SHA256_DIGEST_LENGTH) {
		SHA256_Init(&bodyHash);
		gettimeofday(&tstamp, NULL);
	}
};

bool reqPreProcessing(evhtp_request_t *req, ReqState *state);
Unisrv::View *getView(const std::string& name,
		     const std::string& driver_,
		     const std::string& path);

#endif // __SRV_H__
