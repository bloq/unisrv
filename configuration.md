
# Unisrv Configuration

The database server is configured using a JSON configuration file.

There are three sections to this file:

1. Database views
2. Network endpoints
3. Authentication
4. Miscellaneous

The default filename is `config-srv.json`.  This may be changed using
the `--config` option:

	$ ./unisrvd --config myfile.json

## Database views configuration

This section lists all the database on the local filesystem we wish to
export.

	"views": [
		{
			"name": "data-rocks",
			"path": "./srvdb",
			"driver": "rocksdb"
		},
		{
			"name": "data-gdbm",
			"path": "./srvgdbm",
			"driver": "gdbm"
		}
	],

## Network endpoints configuration

This section lists all the network endpoints exported by the server.

	"endpoints": [
		{
			"name": "ep-gdbm",
			"urlpath": "/gdbm",
			"protocol": "jsonrpc",
			"view": "data-gdbm",
			"readonly": false,
			"auth": "default"
		},
		{
			"name": "ep-rocks",
			"urlpath": "/rocks",
			"protocol": "rest",
			"view": "data-rocks",
			"readonly": false,
			"auth": "default"
		}
	],

## Authentication configuration

This section specifies the list of authentication methods, and their
associated user databases.

	"authentication": [
		{
			"name": "default",
			"method": "simple",
			"username": "testuser",
			"secret": "testpass"
		}
	],

## Miscellaneous configuration

	"bindAddress": "127.0.0.1",
	"bindPort": 8989,
	"daemon": true,
	"pidFile": "/tmp/unisrvd.pid"

