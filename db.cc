
#include "unisrv-config.h"

#include "srv.h"
#include "drivers/rocksdb.h"
#include "drivers/gdbm.h"

using namespace std;

Unisrv::View *getView(const std::string& name,
		     const std::string& driver_,
		     const std::string& path)
{
	string driver = driver_;
	if (name.empty() || path.empty())
		return nullptr;
	if (driver.empty())
		driver = "rocksdb";

	Unisrv::View *view = nullptr;

	if (driver == "rocksdb")
		view = new Unisrv::RocksView(name, path);

	else if (driver == "gdbm")
		view = new Unisrv::GdbmView(name, path);

	else {
		// unknown driver ; do nothing
	}

	if (!view)
		return nullptr;

	if (!view->open()) {
		delete view;
		return nullptr;
	}

	return view;
}

