#ifndef __SRV_H__
#define __SRV_H__

#include <sys/time.h>
#include <string>
#include <vector>
#include <cstdint>
#include <evhtp.h>
#include <univalue.h>
#include <openssl/sha.h>
#include "rocksdb/db.h"

#define DEFAULT_DATASTORE_FN "srv.rocks"

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

	const struct HttpApiEntry *apiEnt;

	ReqState() : md(SHA256_DIGEST_LENGTH) {
		SHA256_Init(&bodyHash);
		gettimeofday(&tstamp, NULL);
	}
};

bool reqPreProcessing(evhtp_request_t *req, ReqState *state);

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
};

class RocksView : public View {
private:
	rocksdb::DB*		db;
	rocksdb::Options	options;

	bool retstat(const rocksdb::Status& status) {
		if (!status.ok())
			errstr_ = status.ToString();
		return status.ok();
	}
public:
	RocksView(const std::string& name, const std::string& path) :
		View(name, "rocksdb", path) {
		db = nullptr;
		options.create_if_missing = true;
	}
	~RocksView() {
		close();
	}

	bool open() {
		rocksdb::Status status =
			rocksdb::DB::Open(options, path_, &db);
		return retstat(status);
	}

	void close() {
		if (db) {
			delete db;
			db = nullptr;
		}
	}

	bool get(const std::string& key, std::string *val) {
		rocksdb::Status status =
			db->Get(rocksdb::ReadOptions(), key, val);
		return retstat(status);
	}

	bool put(const std::string& key, const std::string& val) {
		rocksdb::Status status =
			db->Put(rocksdb::WriteOptions(), key, val);
		return retstat(status);
	}
};

}

#endif // __SRV_H__
