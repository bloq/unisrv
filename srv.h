#ifndef __SRV_H__
#define __SRV_H__

#include <sys/time.h>
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <evhtp.h>
#include <univalue.h>
#include <openssl/sha.h>

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

	std::string	authName;

	bool		wantInput;
};

class DbDriver {
protected:
	std::string		name_;

public:
	DbDriver(const std::string& name) {
		name_ = name;
	}
	virtual ~DbDriver() {}

	const std::string& name() const { return name_; }

	virtual View *newView(const std::string& name, const std::string& path) = 0;
};

class DbRegistry {
public:
	std::map<std::string,DbDriver*>	drivers;

	void add(DbDriver *newDriver) {
		drivers[newDriver->name()] = newDriver;
	}

	void nameList(std::vector<std::string>& names) const {
		names.clear();
		for (auto it = drivers.begin(); it != drivers.end(); it++) {
			names.push_back(it->first);
		}
	}

	View *newView(const std::string& name, const std::string& driverName,
		      const std::string& path) {
		if (drivers.count(driverName) == 0)
			return nullptr;

		DbDriver *driver = drivers[driverName];
		return driver->newView(name, path);
	}
};

class AuthInfo {
public:
	std::string		name;
	std::string		method;

	std::string		dbPath;

	std::map<std::string,std::string> secrets;
};

} // namespace Unisrv

struct HttpApiEntry {
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
bool register_db_drivers();
void list_db_drivers(std::vector<std::string>& names);
void dump_drivers();

#endif // __SRV_H__
