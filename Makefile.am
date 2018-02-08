
AM_CPPFLAGS = -std=c++11 $(PTHREAD_CFLAGS) -I$(top_srcdir)/include
DISTCHECK_CONFIGURE_FLAGS = CXXFLAGS="-O2 -Wall -g -I/usr/local/include/evhtp"

sbin_PROGRAMS = srv dbadm

noinst_LIBRARIES = libcommon.a

libcommon_a_SOURCES = \
	tinyformat.h \
	utilstrencodings.h \
	utilstrencodings.cpp \
	Util.h Util.cc

srv_SOURCES = \
	srv.h srv.cc \
	HttpUtil.h HttpUtil.cc

srv_LDFLAGS = $(PTHREAD_CFLAGS) $(OPENSSL_LDFLAGS)
srv_LDADD = \
	libcommon.a \
	$(PTHREAD_LIBS)		\
	-levhtp \
	-lunivalue \
	-levent_core -levent_openssl \
	$(OPENSSL_LIBS) $(ARGP_LIB) $(UUID_LIB) $(ROCKS_LIB) $(ZMQ_LIB)

dbadm_SOURCES = dbadm.cc
dbadm_LDFLAGS = $(PTHREAD_CFLAGS) $(OPENSSL_LDFLAGS)
dbadm_LDADD = \
	libcommon.a \
	$(PTHREAD_LIBS)		\
	-lunivalue \
	$(OPENSSL_LIBS) $(ARGP_LIB) $(UUID_LIB) $(ROCKS_LIB)

EXTRA_DIST = srv-tests.sh test-config-srv.json
TESTS = srv-tests.sh

