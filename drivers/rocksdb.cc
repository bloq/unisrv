
#include "rocksdb/db.h"
#include "srv.h"

namespace Unisrv {

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

	bool del(const std::string& key) {
		rocksdb::Status status =
			db->Delete(rocksdb::WriteOptions(), key);
		return retstat(status);
	}
};

class RocksDriver : public DbDriver {
public:
	RocksDriver() : DbDriver("rocksdb") {}
	~RocksDriver() {}

	View *newView(const std::string& name, const std::string& path) {
		return new Unisrv::RocksView(name, path);
	}
};

} // namespace Unisrv

Unisrv::DbDriver *new_rocksdb_driver()
{
	return new Unisrv::RocksDriver();
}

