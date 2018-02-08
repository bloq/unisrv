// Copyright (c) 2017 Object Computing, Inc.
// All rights reserved.
// See the file license.txt for licensing information.

#include <string>
#include <vector>
#include <sys/socket.h>
#include <univalue.h>
#include <time.h>

std::string addressToStr(const struct sockaddr *sockaddr, socklen_t socklen);
std::string formatTime(const std::string& fmt, time_t t);
bool readJsonFile(const std::string& filename, UniValue& jval);
std::string isoTimeStr(time_t t);
int write_pid_file(const std::string& pidFn);

