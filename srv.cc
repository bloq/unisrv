
#include "unisrv-config.h"

#include <algorithm>
#include <string>
#include <vector>
#include <map>
#include <locale>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <argp.h>
#include <event2/event_struct.h>
#include <unistd.h>
#include <evhtp.h>
#include <ctype.h>
#include <syslog.h>
#include <assert.h>
#include <univalue.h>
#include "Util.h"
#include "HttpUtil.h"
#include "srv.h"

using namespace std;

#define PROGRAM_NAME "unisrvd"
#define DEFAULT_PID_FILE "/var/run/unisrvd.pid"
#define DEFAULT_BIND_ADDR "0.0.0.0"
#define DEFAULT_DB_NAME "srvdb"

enum {
	MAX_CLIENT_DRIFT	= 20,	// max seconds client time may drift

	DEFAULT_PORT		= 8989,
};

static const char doc[] =
PROGRAM_NAME " - rpc server";

static struct argp_option options[] = {
	{ "config", 'c', "FILE", 0,
	  "JSON server configuration file (default: config-srv.json)" },

	{ "daemon", 1002, NULL, 0,
	  "Daemonize; run server in background." },

	{ "dump-config", 1004, NULL, 0,
	  "Do not run server; output configuration instead" },
	{ "dump-drivers", 1005, NULL, 0,
	  "Do not run server; output list of Db drivers instead" },

	{ "pid-file", 'p', "FILE", 0,
	  "Pathname to which process PID is written (default: " DEFAULT_PID_FILE "; empty string to disable)" },
	{ }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);
static const struct argp argp = { options, parse_opt, NULL, doc };

static std::string opt_configfn = "config-srv.json";
static std::string opt_pid_file = DEFAULT_PID_FILE;
static bool opt_daemon = false;
static bool opt_dump_config = false;
static bool opt_dump_drivers = false;
static UniValue serverCfg;
static evbase_t *evbase = NULL;

static map<string,Unisrv::View*> dbViews;
static map<string,Unisrv::Endpoint> srvEndpoints;

static map<string,Unisrv::AuthInfo> authInfo;

static void
logRequest(evhtp_request_t *req, ReqState *state)
{
	assert(req && state);

	// IP address
	string addrStr = addressToStr(req->conn->saddr,
				      sizeof(struct sockaddr)); // TODO verify

	// request timestamp.  use request-completion (not request-start)
	// time instead?
	struct tm tm;
	gmtime_r(&state->tstamp.tv_sec, &tm);

	// get http method, build timestamp str
	string timeStr = isoTimeStr(state->tstamp.tv_sec);
	htp_method method = evhtp_request_get_method(req);
	const char *method_name = htparser_get_methodstr_m(method);

	// output log line
	printf("%s - - [%s] \"%s %s\" ? %lld\n",
		addrStr.c_str(),
		timeStr.c_str(),
		method_name,
		req->uri->path->full,
		(long long) get_content_length(req));
}

static evhtp_res
upload_read_cb(evhtp_request_t * req, evbuf_t * buf, void * arg)
{
	assert(req && buf && arg);

	ReqState *state = (ReqState *) arg;

	// remove data from evbuffer to malloc'd buffer
	size_t bufsz = evbuffer_get_length(buf);
	char *chunk = (char *) malloc(bufsz);
	int rc = evbuffer_remove(buf, chunk, bufsz);
	assert(rc == (int) bufsz);

	// append chunk to total body
	state->body.append(chunk, bufsz);

	// update in-progress content hash
	SHA256_Update(&state->bodyHash, chunk, bufsz);

	// release malloc'd buffer
	free(chunk);

	return EVHTP_RES_OK;
}

static evhtp_res
req_finish_cb(evhtp_request_t * req, void * arg)
{
	assert(req && arg);

	ReqState *state = (ReqState *) arg;

	// log request, following processing
	logRequest(req, state);

	// release our per-request state
	delete state;

	return EVHTP_RES_OK;
}

static void reqInit(evhtp_request_t *req, ReqState *state,
		    Unisrv::Endpoint *endpt)
{
	assert(req && state && endpt);

	state->endpt = endpt;
	state->apiEnt = &state->apiEnt_;

	state->apiEnt_.cb = nullptr;
	state->apiEnt_.path = endpt->urlpath.c_str();
	state->apiEnt_.wantInput = endpt->wantInput;
	if (endpt->protocol == "jsonrpc")
		state->apiEnt_.jsonInput = true;

	// standard Date header
	evhtp_headers_add_header(req->headers_out,
		evhtp_header_new("Date",
			 httpDateHdr(state->tstamp.tv_sec).c_str(),
			 0, 1));

	// standard Server header
	const char *serverVer = PROGRAM_NAME "/" PACKAGE_VERSION;
	evhtp_headers_add_header(req->headers_out,
		evhtp_header_new("Server", serverVer, 0, 0));

	// assign our global (to a request) state
	req->cbarg = state;

	// assign request completion hook
	evhtp_request_set_hook (req, evhtp_hook_on_request_fini, (evhtp_hook) req_finish_cb, state);
}

static bool reqVerify(evhtp_request_t *req,
		      const std::string& authUser,
		      const std::string& authSecret)
{
	assert(req);

	// input remote Auth hdr
	const char *authcstr = evhtp_kv_find (req->headers_in, "Authorization");
	if (!authcstr)
		return false;
	string authHdr(authcstr);

	// generate local Auth hdr
	string authCanonical;
	basic_auth_hdr(authUser, authSecret, authCanonical);

	// verify match
	return (authHdr == authCanonical);
}

bool reqPreProcessing(evhtp_request_t *req, ReqState *state)
{
	assert(req && state && state->apiEnt);

	const struct HttpApiEntry *apiEnt = state->apiEnt;
	Unisrv::Endpoint *endpt = state->endpt;

	// check authorization, if method requires it
	if (!endpt->authName.empty()) {
		assert(authInfo.count(endpt->authName) > 0);
		Unisrv::AuthInfo ai = authInfo[endpt->authName];

		if (ai.method == "simple") {
			auto it = ai.secrets.begin();
			string authUser = it->first;
			string authSecret = it->second;
			if (!reqVerify(req, authUser, authSecret)) {
				evhtp_send_reply(req, EVHTP_RES_FORBIDDEN);
				return false;
			}
		} else {
			assert(0);
		}
	}

	// parse JSON input, if API entry requires it
	state->jval.clear();
	if (apiEnt->wantInput && apiEnt->jsonInput) {
		if (!state->body.empty() &&
		    !state->jval.read(state->body)) {
			evhtp_send_reply(req, EVHTP_RES_BADREQ);
			return false;
		}
	}

	return true;
}

static evhtp_res
upload_headers_cb(evhtp_request_t * req, evhtp_headers_t * hdrs, void *arg)
{
	assert(req && hdrs && arg);

	Unisrv::Endpoint *endpt = (Unisrv::Endpoint *) arg;

	// handle OPTIONS
	if (evhtp_request_get_method(req) == htp_method_OPTIONS) {
		return EVHTP_RES_OK;
	}

	// alloc new per-request state
	ReqState *state = new ReqState();
	assert(state != NULL);

	// common per-request state
	reqInit(req, state, endpt);

	// special incoming-data hook
	evhtp_request_set_hook (req, evhtp_hook_on_read, (evhtp_hook) upload_read_cb, state);

	return EVHTP_RES_OK;
}

static evhtp_res
no_upload_headers_cb(evhtp_request_t * req, evhtp_headers_t * hdrs, void *arg)
{
	assert(req && hdrs && arg);

	Unisrv::Endpoint *endpt = (Unisrv::Endpoint *) arg;

	// handle OPTIONS
	if (evhtp_request_get_method(req) == htp_method_OPTIONS) {
		return EVHTP_RES_OK;
	}

	// alloc new per-request state
	ReqState *state = new ReqState();
	assert(state != NULL);

	// common per-request state
	reqInit(req, state, endpt);

	return EVHTP_RES_OK;
}

static void rest_get(evhtp_request_t *req, ReqState *state,
		     Unisrv::Endpoint *endpt)
{
	string key(req->uri->path->match_start);
	string value;
	bool rc = endpt->view->get(key, &value);
	if (!rc) {
		evhtp_send_reply(req, EVHTP_RES_NOTFOUND);
		return;
	}

	evhtp_headers_add_header(req->headers_out,
		evhtp_header_new("Content-Type", "application/octet-stream", 0, 0));
	evbuffer_add(req->buffer_out, value.c_str(), value.size());
	evhtp_send_reply(req, EVHTP_RES_OK);
}

static void rest_put(evhtp_request_t *req, ReqState *state,
		     Unisrv::Endpoint *endpt)
{
	string key(req->uri->path->match_start);
	bool rc = endpt->view->put(key, state->body);
	if (!rc) {
		evhtp_send_reply(req, EVHTP_RES_SERVERR);
		return;
	}

	evhtp_send_reply(req, EVHTP_RES_OK);
}

static void rest_del(evhtp_request_t *req, ReqState *state,
		     Unisrv::Endpoint *endpt)
{
	string key(req->uri->path->match_start);
	bool rc = endpt->view->del(key);
	if (!rc) {
		evhtp_send_reply(req, EVHTP_RES_NOTFOUND);
		return;
	}

	evhtp_send_reply(req, EVHTP_RES_OK);
}

static void http_req_rest(evhtp_request_t *req, ReqState *state,
		   Unisrv::Endpoint *endpt)
{
	if (req->method == htp_method_GET)
		rest_get(req, state, endpt);
	else if (req->method == htp_method_PUT)
		rest_put(req, state, endpt);
	else if (req->method == htp_method_DELETE)
		rest_del(req, state, endpt);

	else {
		evhtp_send_reply(req, EVHTP_RES_METHNALLOWED);
	}
}

static bool validJsonRpc(const UniValue& val)
{
	std::map<std::string,UniValue::VType> schema;
	schema["method"] = UniValue::VSTR;
	if (!val.checkObject(schema))
		return false;

	const UniValue& method = val["method"];
	if (method.getValStr().empty())
		return false;

	if (val.exists("params")) {
		const UniValue& params = val["params"];
		if ((params.getType() != UniValue::VARR) &&
		    (params.getType() != UniValue::VOBJ))
			return false;
	}

	if (val.exists("id")) {
		const UniValue& id = val["id"];
		switch (id.getType()) {
		case UniValue::VSTR:
		case UniValue::VNUM:
		case UniValue::VNULL:
			// do nothing
			break;
		default:
			return false;
		}
	}

	return true;
}

void rpcReply(evhtp_request_t * req, const UniValue& jreq, UniValue& outObj)
{
	outObj.pushKV("jsonrpc", "2.0");
	outObj.pushKV("id", jreq.exists("id") ? jreq["id"] : NullUniValue);

	// successful operation.  Return JSON output.
	httpJsonReply(req, outObj);
}

void rpcReplyOk(evhtp_request_t * req, const UniValue& jreq,
		const UniValue& result)
{
	UniValue obj(UniValue::VOBJ);
	obj.pushKV("result", result);

	rpcReply(req, jreq, obj);
}

void rpcReplyErr(evhtp_request_t * req, const UniValue& jreq,
		 int64_t code, const string& msg)
{
	UniValue errobj(UniValue::VOBJ);
	errobj.pushKV("code", code);
	errobj.pushKV("message", msg);

	UniValue obj(UniValue::VOBJ);
	obj.pushKV("error", errobj);

	rpcReply(req, jreq, obj);
}

void jrpc_get(evhtp_request_t *req, const UniValue& jreq,
	      Unisrv::Endpoint *endpt)
{
	const string& key = jreq["params"][0].getValStr();
	if (key.empty()) {
		rpcReplyErr(req, jreq, -32602, "Invalid params: first param missing/not a string");
		return;
	}

	string value;
	bool rc = endpt->view->get(key, &value);
	if (!rc)
		rpcReplyErr(req, jreq, -1, "Key not found");
	else
		rpcReplyOk(req, jreq, UniValue(value));
}

void jrpc_put(evhtp_request_t *req, const UniValue& jreq,
	      Unisrv::Endpoint *endpt)
{
	const string& key = jreq["params"][0].getValStr();
	const string& value = jreq["params"][1].getValStr();
	if (key.empty()) {
		rpcReplyErr(req, jreq, -32602, "Invalid params: first param missing/not a string");
		return;
	}

	bool rc = endpt->view->put(key, value);
	if (!rc)
		rpcReplyErr(req, jreq, -1, "Key/value store failed");
	else
		rpcReplyOk(req, jreq, UniValue(true));
}

void jrpc_del(evhtp_request_t *req, const UniValue& jreq,
	      Unisrv::Endpoint *endpt)
{
	const string& key = jreq["params"][0].getValStr();
	if (key.empty()) {
		rpcReplyErr(req, jreq, -32602, "Invalid params: first param missing/not a string");
		return;
	}

	bool rc = endpt->view->del(key);
	if (!rc)
		rpcReplyErr(req, jreq, -1, "Key delete failed");
	else
		rpcReplyOk(req, jreq, UniValue(true));
}

void http_req_jsonrpc(evhtp_request_t *req, const UniValue& jreq,
		      Unisrv::Endpoint *endpt)
{
	if (!validJsonRpc(jreq)) {
		evhtp_send_reply(req, EVHTP_RES_BADREQ);
		return;
	}

	const string& method = jreq["method"].getValStr();

	if (method == "get")
		jrpc_get(req, jreq, endpt);
	else if (method == "put")
		jrpc_put(req, jreq, endpt);
	else if (method == "del")
		jrpc_del(req, jreq, endpt);

	else {
		rpcReplyErr(req, jreq, -32601, "Method not found");
	}
}

void http_req_cb(evhtp_request_t * req, void * arg)
{
	assert(req && arg);
	ReqState *state = (ReqState *) arg;
	Unisrv::Endpoint *endpt = state->endpt;

	// global pre-request processing
	if (!reqPreProcessing(req, state))
		return;		// pre-processing failed; response already sent

	if (endpt->protocol == "jsonrpc")
		http_req_jsonrpc(req, state->jval, endpt);
	else if (endpt->protocol == "rest")
		http_req_rest(req, state, endpt);
	else {
		assert(0);	// should never happen
	}
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'c':
		opt_configfn = arg;
		break;

	case 'p':
		opt_pid_file = arg;
		break;

	case 1002:
		opt_daemon = true;
		break;

	case 1004:
		opt_dump_config = true;
		break;
	case 1005:
		opt_dump_drivers = true;
		break;

	case ARGP_KEY_END:
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static bool init_endpoints()
{
	const UniValue& endpointsList = serverCfg["endpoints"];
	for (unsigned int i = 0; i < endpointsList.size(); i++) {
		const UniValue& endpointCfg = endpointsList[i];

		Unisrv::Endpoint endpt;
		endpt.name = endpointCfg["name"].getValStr();
		endpt.urlpath = endpointCfg["urlpath"].getValStr();
		endpt.protocol = endpointCfg["protocol"].getValStr();
		if (endpt.protocol.empty())
			endpt.protocol = "jsonrpc";
		const string& viewName = endpointCfg["view"].getValStr();
		endpt.wantInput = !endpointCfg["readonly"].isTrue();

		endpt.authName = endpointCfg["auth"].getValStr();
		if (endpt.authName.empty()) {
			// do nothing; no auth
		} else if (authInfo.count(endpt.authName) == 0) {
			syslog(LOG_ERR, "endpoint %s: unknown auth %s\n",
				endpt.name.c_str(),
				endpt.authName.c_str());
			return false;
		}

		if (endpt.name.empty() || endpt.urlpath.empty() ||
		    viewName.empty()) {
			syslog(LOG_ERR, "endpoint details missing\n");
			return false;
		}
		if (endpt.urlpath[0] != '/') {
			syslog(LOG_ERR, "endpoint %s: invalid urlpath\n",
				endpt.name.c_str());
			return false;
		}
		if ((endpt.protocol != "jsonrpc") &&
		    (endpt.protocol != "rest")) {
			syslog(LOG_ERR, "endpoint %s: invalid protocol\n",
				endpt.name.c_str());
			return false;
		}
		if (dbViews.count(viewName) == 0) {
			syslog(LOG_ERR, "endpoint %s: unknown view %s\n",
				endpt.name.c_str(),
				viewName.c_str());
			return false;
		}

		endpt.view = dbViews[viewName];

		srvEndpoints[endpt.name] = endpt;
	}

	return true;
}


static bool init_db_views()
{
	const UniValue& viewsList = serverCfg["views"];
	for (unsigned int i = 0; i < viewsList.size(); i++) {
		const UniValue& viewCfg = viewsList[i];
		const string& viewName = viewCfg["name"].getValStr();

		Unisrv::View *view = getView(
			viewName,
			viewCfg["driver"].getValStr(),
			viewCfg["path"].getValStr());
		if (view == nullptr) {
			syslog(LOG_ERR, "failed to open view %s\n",
				viewName.c_str());
			return false;
		}

		dbViews[viewName] = view;
	}

	return true;
}

static bool init_auth()
{
	const UniValue& authList = serverCfg["authentication"];
	for (unsigned int i = 0; i < authList.size(); i++) {
		const UniValue& authCfg = authList[i];
		const string& authName = authCfg["name"].getValStr();

		Unisrv::AuthInfo ai;
		ai.name = authName;
		ai.method = authCfg["method"].getValStr();
		if (ai.method == "simple") {
			string un = authCfg["username"].getValStr();
			string pw = authCfg["secret"].getValStr();
			ai.secrets[un] = pw;
		} else if (ai.method == "table") {
			std::map<std::string,UniValue> tbl;
			authCfg["table"].getObjMap(tbl);
			for (auto it = tbl.begin(); it != tbl.end(); it++) {
				ai.secrets[it->first] = it->second.getValStr();
			}
		} else {
			syslog(LOG_ERR, "invalid auth method");
			return false;
		}

		authInfo[authName] = ai;
	}

	return true;
}

static bool read_config_init()
{
	if (access(opt_configfn.c_str(), F_OK) == 0) {
		if (!readJsonFile(opt_configfn, serverCfg)) {
			perror(opt_configfn.c_str());
			return false;
		}
	} else {
		syslog(LOG_WARNING, "Config file absent, continuing with built-in defaults\n");
	}

	if (!serverCfg.exists("bindAddress"))
		serverCfg.pushKV("bindAddress", DEFAULT_BIND_ADDR);
	if (!serverCfg.exists("bindPort"))
		serverCfg.pushKV("bindPort", (int64_t) DEFAULT_PORT);
	if (serverCfg.exists("daemon"))
		opt_daemon = serverCfg["daemon"].getBool();
	if (serverCfg.exists("pidFile"))
		opt_pid_file = serverCfg["pidFile"].getValStr();

	return true;
}

static void pid_file_cleanup(void)
{
	if (!opt_pid_file.empty())
		unlink(opt_pid_file.c_str());
}

static void shutdown_signal(int signo)
{
	event_base_loopbreak(evbase);
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

	openlog(PROGRAM_NAME, LOG_PID | LOG_PERROR, LOG_USER);

	// read json configuration, and initialize early defaults
	if (!read_config_init())
		return EXIT_FAILURE;

	// Process auto-cleanup
	signal(SIGTERM, shutdown_signal);
	signal(SIGINT, shutdown_signal);
	atexit(pid_file_cleanup);

	// initialize libevent, libevhtp
	evbase = event_base_new();
	evhtp_t  * htp    = evhtp_new(evbase, NULL);
	evhtp_callback_t *cb = NULL;

	if (!register_db_drivers())
		return EXIT_FAILURE;
	if (opt_dump_drivers) {
		dump_drivers();
		return EXIT_SUCCESS;
	}

	if (!init_auth() || !init_db_views() || !init_endpoints())
		return EXIT_FAILURE;

	if (dbViews.empty()) {
		syslog(LOG_ERR, "no db views, exiting\n");
		return EXIT_FAILURE;
	}
	if (srvEndpoints.empty()) {
		syslog(LOG_ERR, "no endpoints, exiting\n");
		return EXIT_FAILURE;
	}

	// register our list of API calls and their handlers
	for (auto it = srvEndpoints.begin(); it != srvEndpoints.end(); it++) {
		Unisrv::Endpoint *endpt = &srvEndpoints[it->first];

		// register evhtp hook
		if (endpt->protocol == "rest") {
			string rx = "^" + endpt->urlpath;
			if (rx[rx.size() - 1] != '/')
				rx += "/";
			rx += "(.*)";

			cb = evhtp_set_regex_cb(htp, rx.c_str(),
						http_req_cb, (void *) endpt);
		} else
			cb = evhtp_set_cb(htp, endpt->urlpath.c_str(),
					  http_req_cb, (void *) endpt);

		// set standard per-callback initialization hook
		evhtp_callback_set_hook(cb, evhtp_hook_on_headers,
			endpt->wantInput ?
				((evhtp_hook) upload_headers_cb) :
				((evhtp_hook) no_upload_headers_cb), (void *) endpt);
	}

	// Daemonize
	if (opt_daemon && daemon(0, 0) < 0) {
		perror("Failed to daemonize");
		return EXIT_FAILURE;
	}

	// Hold open PID file until process exits
	int pid_fd = write_pid_file(opt_pid_file);
	if (pid_fd < 0)
		return EXIT_FAILURE;

	if (opt_dump_config) {
		printf("%s\n", serverCfg.write(2).c_str());
		return EXIT_SUCCESS;
	}

	// bind to socket and start server main loop
	evhtp_bind_socket(htp,
			  serverCfg["bindAddress"].getValStr().c_str(),
			  atoi(serverCfg["bindPort"].getValStr().c_str()),
			  1024);

	syslog(LOG_INFO, "initialized; ready for socket activity");

	event_base_loop(evbase, 0);

	syslog(LOG_INFO, "shutdown complete.");
	return 0;
}
