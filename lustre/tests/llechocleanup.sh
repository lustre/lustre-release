#!/bin/sh

LCONF=../utils/lconf

if [ -f echo.xml ]; then
   ${LCONF} --cleanup echo.xml
else
   echo "no echo.xml found"
fi

