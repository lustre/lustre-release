if [ -d /r ]; then
  R=/r
fi

if [ -b /dev/loop0 ]; then
  LOOP=/dev/loop
else
  if [ -b /dev/loop/0 ]; then
    LOOP=/dev/loop/
  else
    echo "Cannot find /dev/loop0 or /dev/loop/0";
    exit -1
  fi
fi
