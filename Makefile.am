
AM_CPPFLAGS = $(PTHREAD_CFLAGS) -I$(top_srcdir)
DISTCHECK_CONFIGURE_FLAGS = CXXFLAGS="-O2 -Wall -g -I/usr/local/include/evhtp"

sbin_PROGRAMS = unisrvd dbtool

noinst_LIBRARIES = libcommon.a libdbdriver.a

libdbdriver_a_SOURCES = \
	db.cc \
	drivers/rocksdb.cc \
	drivers/gdbm.cc

libcommon_a_SOURCES = \
	tinyformat.h \
	utilstrencodings.h \
	utilstrencodings.cpp \
	Util.h Util.cc

unisrvd_SOURCES = \
	srv.h srv.cc \
	HttpUtil.h HttpUtil.cc

unisrvd_LDFLAGS = $(PTHREAD_CFLAGS) $(OPENSSL_LDFLAGS)
unisrvd_LDADD = \
	libcommon.a \
	libdbdriver.a \
	$(PTHREAD_LIBS)		\
	-levhtp \
	-lunivalue \
	-levent_core -levent_openssl \
	$(OPENSSL_LIBS) $(ARGP_LIB) $(UUID_LIB) $(DB_LIBS)

dbtool_SOURCES = dbtool.cc
dbtool_LDFLAGS = $(PTHREAD_CFLAGS) $(OPENSSL_LDFLAGS)
dbtool_LDADD = \
	libcommon.a \
	libdbdriver.a \
	$(PTHREAD_LIBS)		\
	-lunivalue \
	$(OPENSSL_LIBS) $(ARGP_LIB) $(UUID_LIB) $(DB_LIBS)

EXTRA_DIST = srv-tests.sh test-config-srv.json
TESTS = srv-tests.sh

