
# Unisrv: Universal NoSQL database server

Unisrv is a database server:  a microservice that exports local
filesystem databases over a network.  It is the swiss army knife of
db services.

Unisrv can export a gdbm database over HTTP REST, a rocksdb database
over JSON-RPC, and more.  You can mix and match database type, network
protocol interface and authentication methods.

## Supported database types

The following database types are supported:

* gdbm
* Rocksdb

## Supported network protocols

You may export the database via any number of network protocols:

* REST over HTTP
* JSON-RPC over HTTP

### HTTP endpoint sharing

Multiple HTTP paths at the same HTTP endpoint are supported; for example

	http://127.0.0.1:8989/data/mydata

might export a gdbm database, while the same HTTP endpoint may also
export a separate dataset from rocksdb at

	http://127.0.0.1:8989/rocks

## Dependencies

* OpenSSL
* One or more database libraries
* libevhtp: https://github.com/criticalstack/libevhtp

## Building and installing

This uses the standard autotools pattern:

	$ ./autogen.sh
	$ CXXFLAGS="-O2 -Wall -g -I/usr/local/include/evhtp" ./configure
	$ make			# compile
	$ make check		# run tests
	$ sudo make install	# install on system

