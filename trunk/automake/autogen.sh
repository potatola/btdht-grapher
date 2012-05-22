#!/bin/bash
touch NEWS README ChangeLog AUTHORS
aclocal
autoconf
automake -a
./configure
