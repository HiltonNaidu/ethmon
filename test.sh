#!/usr/bin/env bash

mkdir test_info
ethmon --help > test_info/ethmon_help.txt
ethmon --version > test_info/ethmon_version.txt
ethmon add --help > test_info/ethmon_add_help.txt
