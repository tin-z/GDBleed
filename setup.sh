#!/bin/bash


if [ "$1" == "--clean" ]; then
  rm -rf keystone keystone_repo LIEF lief.so r2pipe
  exit 1
fi

###
## 0. Prereq 
#

if [ -z "$PYTHON_VER" ]; then
  echo "[!] Before continuing change/declare the 'PYTHON_VER' env var to the version of python which you intend to build on (refer to gdb python api version)"
  exit 1
fi

if [ -z "`which unzip`" ]; then
  echo "[!] 'unzip' is no present, install it before continuing"
  exit 1
fi

if [ -z "`which cmake`" ]; then
  echo "[!] 'cmake' is no present, install it before continuing"
  exit 1
fi

if [ -z "`which readelf`" ]; then
  echo "[!] 'readelf' is no present, install it before continuing"
  exit 1
fi

if [ -z "`which radare2`" ]; then
  echo "[!] 'radare2' is no present, install it before continuing"
  echo ""
  echo "wget https://github.com/radareorg/radare2/releases/download/5.5.0/radare2_5.5.0_amd64.deb"
  echo "dpkg -i ./radare2_5.5.0_amd64.deb"
  echo ""
  echo "Set file '~/.radare2rc' as"
  # Show comments at right of disassembly if they fit in screen
  echo "e asm.cmt.right=true"
  # Shows pseudocode in disassembly. Eg mov eax, str.ok = > eax = str.ok
  #echo "e asm.pseudo = true"
  # Solarized theme
  echo "eco solarized"
  echo "e scr.utf8 = true"
  echo ""
  exit 1
fi

if [ -z "`which virtualenv`" ]; then
  echo "[!] Install: 'sudo apt-get install ${PYTHON_VER}-distutils ${PYTHON_VER}-setuptools virtualenv'"
  echo ""
  exit 1
fi

if [ ! -f .gdbinit-gef.py ]; then
  wget -O ./.gdbinit-gef.py -q https://gef.blah.cat/py
fi


###
## 1. Instal keystone python module
#
if [ ! -d keystone_repo ]; then
  echo "[!] 'keystone' is no present ... installing it now (only on current folder)"

  if [ -z "$KEYSTONE_VER" ]; then
    echo "[!] Before continuing the variable 'KEYSTONE_VER' should be declared (e.g export KEYSTONE_VER=\"0.9.2\") ...quit"
    exit 1
  fi

  wget https://github.com/keystone-engine/keystone/archive/refs/tags/${KEYSTONE_VER}.zip
  unzip ${KEYSTONE_VER}.zip
  rm ${KEYSTONE_VER}.zip

  mv keystone-${KEYSTONE_VER} keystone_repo
  cd keystone_repo/bindings/python

  $PYTHON_VER setup.py build
  cd ../../..
  mv keystone_repo/bindings/python/keystone .
fi


###
## 2. Check LIEF
#
#if [ ! -f lief.so ]; then
#  echo "[!] 'LIEF' is no present ... installing it now (only on current folder)"
#
#  wget https://github.com/lief-project/LIEF/archive/refs/tags/${LIEF_VER}.zip
#  unzip ${LIEF_VER}.zip
#  rm ${LIEF_VER}.zip
#
#  mv LIEF-${LIEF_VER} LIEF
#  cd LIEF
#  $PYTHON_VER setup.py build
#
#  if [ $? != 0 ]; then
#    echo "[!] error while building LIEF module"
#    echo " \---> Run 'sudo apt-get install ${PYTHON_VER}-distutils ${PYTHON_VER}-setuptools'"
#    exit
#  fi
#
#  cd ..
#  mv LIEF/build/lief.so .
#
#fi


#if [ ! -d keystone ]; then
#  echo "[!] 'keystone' is no present ... installing it now (only on current folder)"
#  rm -rf object_virtualenv; mkdir object_virtualenv && virtualenv --python=$PYTHON_VER object_virtualenv &&\
#  source object_virtualenv/bin/activate &&\
#  pip install keystone &&\
#  deactivate
#
#  find -name keystone -type d | while read x; do
#    mv "$x" keystone
#  done
#
#  rm -rf object_virtualenv
#fi

if [ ! -f lief.so ]; then
  echo "[!] 'LIEF' is no present ... installing it now (only on current folder)"
  rm -rf object_virtualenv; mkdir object_virtualenv && virtualenv --python=$PYTHON_VER object_virtualenv &&\
  source object_virtualenv/bin/activate &&\
  pip install lief==${LIEF_VER} &&\
  deactivate

  find -name "lief*.so" -type f | while read x; do
    mv "$x" lief.so
  done

  rm -rf object_virtualenv
fi

if [ ! -d r2pipe ]; then
  echo "[!] 'r2pipe' is no present ... installing it now (only on current folder)"
  rm -rf object_virtualenv; mkdir object_virtualenv && virtualenv --python=$PYTHON_VER object_virtualenv &&\
  source object_virtualenv/bin/activate &&\
  pip install r2pipe &&\
  deactivate

  find -name r2pipe -type d | while read x; do
    mv "$x" r2pipe
  done

  rm -rf object_virtualenv
fi


echo "[+] All requirements are met"
echo ""
echo "Now we need to declare env 'GDBLEED_HOME', you can do it like so:"
echo "echo \"export GDBLEED_HOME=$PWD\" >> ~/.bashrc"
echo "export GDBLEED_HOME=$PWD"


echo "[+] Done!"

