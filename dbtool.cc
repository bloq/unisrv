
#include "unisrv-config.h"

#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <map>
#include <locale>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <argp.h>
#include <unistd.h>
#include <evhtp.h>
#include <ctype.h>
#include <assert.h>
#include <univalue.h>
#include "Util.h"
#include "HttpUtil.h"
#include "srv.h"
#include "rocksdb/db.h"

using namespace std;

#define PROGRAM_NAME "dbtool"

static const char doc[] =
PROGRAM_NAME " - universal db tool";

static struct argp_option options[] = {
	{ "rocksdb", 2001, "FILE", 0,
	  "Rocksdb Database pathname" },

	{ "load-json", 1006, "JSON-FILE", 0,
	  "Load JSON object into db" },

	{ "key-prefix", 1007, "PREFIX", 0,
	  "Prepend this string to each key, during load operations" },

	{ "keys", 1003, NULL, 0,
	  "Dump all keys" },

	{ "dump", 1004, NULL, 0,
	  "Dump all keys and values" },

	{ "dump-drivers", 1008, NULL, 0,
	  "Do not open any database; output list of Db drivers instead" },

	{ "clear", 1005, NULL, 0,
	  "Delete all data, before loading" },

	{ }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp = { options, parse_opt, NULL, doc };

static string opt_db_driver;
static string opt_db_fn;
static string opt_load_json_fn;
static string opt_key_prefix;
static bool opt_dump_drivers = false;
static bool opt_dump_keys = false;
static bool opt_dump_db = false;
static bool opt_clear_db = false;

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {

	case 2001:
		opt_db_driver = "rocksdb";
		opt_db_fn = arg;
		break;

	case 1003:	// --keys
		opt_dump_keys = true;
		break;

	case 1004:	// --dump
		opt_dump_db = true;
		break;

	case 1005:
		opt_clear_db = true;
		break;

	case 1006:
		opt_load_json_fn = arg;
		break;

	case 1007:
		opt_key_prefix = arg;
		break;

	case 1008:
		opt_dump_drivers = true;
		break;

	case ARGP_KEY_END:
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void dbPutJson(rocksdb::DB* db, const std::string& key,
		      const UniValue& jval)
{
	string val = jval.write();

	rocksdb::Status s = db->Put(rocksdb::WriteOptions(), key, val);
	assert(s.ok());
}

static void dbPrefixedLoad(rocksdb::DB* db,
			  const std::string& fn,
			  const std::string& prefix)
{
	UniValue jobj;
	bool rc = readJsonFile(fn, jobj);
	if (!rc) {
		perror(fn.c_str());
		exit(1);
	}

	assert(jobj.getType() == UniValue::VOBJ);

	const std::vector<std::string>& keys = jobj.getKeys();
	const std::vector<UniValue>& values = jobj.getValues();
	for (size_t i = 0; i < keys.size(); i++) {
		dbPutJson(db, prefix + keys[i], values[i]);
	}
}

static void dump_db(rocksdb::DB* db)
{
	rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
	for (it->SeekToFirst(); it->Valid(); it->Next()) {
		cout << it->key().ToString() << ": " << it->value().ToString() << endl;
	}
	assert(it->status().ok()); // Check for any errors found during the scan
	delete it;
}

static void dump_keys(rocksdb::DB* db)
{
	rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
	for (it->SeekToFirst(); it->Valid(); it->Next()) {
		cout << it->key().ToString() << endl;
	}
	assert(it->status().ok()); // Check for any errors found during the scan
	delete it;
}

int main(int argc, char ** argv)
{
	// parse command line
	error_t argp_rc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (argp_rc) {
		fprintf(stderr, "%s: argp_parse failed: %s\n",
			argv[0], strerror(argp_rc));
		return EXIT_FAILURE;
	}

	if (!register_db_drivers()) {
		assert(0);
	}
	if (opt_dump_drivers) {
		dump_drivers();
		return EXIT_SUCCESS;
	}

	if (opt_db_fn.empty()) {
		fprintf(stderr, "No database pathname specified\n");
		return EXIT_FAILURE;
	}

	if (opt_clear_db)
		DestroyDB(opt_db_fn, rocksdb::Options());

	rocksdb::DB* db;
	rocksdb::Options options;
	options.create_if_missing = true;
	rocksdb::Status status =
	  rocksdb::DB::Open(options, opt_db_fn, &db);
	assert(status.ok());

	// input

	if (!opt_load_json_fn.empty())
		dbPrefixedLoad(db, opt_load_json_fn, opt_key_prefix);

	// output

	if (opt_dump_keys)
		dump_keys(db);
	if (opt_dump_db)
		dump_db(db);

	return 0;
}
