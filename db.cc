
#include "unisrv-config.h"

#include "srv.h"

using namespace std;
using namespace Unisrv;

DbRegistry registry;

Unisrv::View *getView(const std::string& name,
		     const std::string& driver_,
		     const std::string& path)
{
	Unisrv::View *view = registry.newView(name, driver_, path);
	if (!view)
		return nullptr;

	if (!view->open()) {
		delete view;
		return nullptr;
	}

	return view;
}

bool register_db_drivers()
{
#ifdef HAVE_GDBM_H
	Unisrv::DbDriver *new_gdbm_driver();
	registry.add(new_gdbm_driver());
#endif

#ifdef HAVE_ROCKSDB_DB_H
	Unisrv::DbDriver *new_rocksdb_driver();
	registry.add(new_rocksdb_driver());
#endif

	return true;
}

void list_db_drivers(std::vector<std::string>& names)
{
	registry.nameList(names);
}

