#ifndef __DRIVERS_GDBM_H__
#define __DRIVERS_GDBM_H__

#include <gdbm.h>
#include "srv.h"

namespace Unisrv {

class GdbmView : public View {
private:
	GDBM_FILE		db;

	bool errstat() {
		errstr_ = gdbm_strerror(gdbm_errno);
		return false;
	}
public:
	GdbmView(const std::string& name, const std::string& path) :
		View(name, "gdbm", path) {
		db = nullptr;
	}
	~GdbmView() {
		close();
	}

	bool open() {
		db = gdbm_open((char *) path_.c_str(), 0, GDBM_WRCREAT, 0666, nullptr);
		if (db)
			return true;
		return errstat();
	}

	void close() {
		if (db) {
			gdbm_close(db);
			db = nullptr;
		}
	}

	bool get(const std::string& key, std::string *val) {
		datum keyDatum;
		keyDatum.dptr = (char *) key.c_str();
		keyDatum.dsize = key.size();

		datum valDatum = gdbm_fetch(db, keyDatum);
		if (valDatum.dptr == nullptr)
			return errstat();

		val->assign(valDatum.dptr, valDatum.dsize);
		free(valDatum.dptr);
		return true;
	}

	bool put(const std::string& key, const std::string& val) {
		datum keyDatum;
		keyDatum.dptr = (char *) key.c_str();
		keyDatum.dsize = key.size();
		datum valueDatum;
		valueDatum.dptr = (char *) val.c_str();
		valueDatum.dsize = val.size();

		int rc = gdbm_store(db, keyDatum, valueDatum, GDBM_REPLACE);
		if (rc != 0)
			return errstat();
		return true;
	}

	bool del(const std::string& key) {
		datum keyDatum;
		keyDatum.dptr = (char *) key.c_str();
		keyDatum.dsize = key.size();

		int rc = gdbm_delete(db, keyDatum);
		if (rc != 0)
			return errstat();
		return true;
	}
};

} // namespace Unisrv

#endif // __DRIVERS_GDBM_H__
