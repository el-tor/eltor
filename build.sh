### on linux
# sudo apt-get install automake libevent-dev zlib1g zlib1g-dev build-essential libssl-dev
# ./autogen.sh
# ./configure --enable-static-tor --enable-static-libevent --enable-static-openssl --enable-static-zlib --disable-asciidoc --with-libevent-dir=/usr/lib/x86_64-linux-gnu --with-openssl-dir=/usr/lib/x86_64-linux-gnu --with-zlib-dir=/usr/lib/x86_64-linux-gnu
# make

### windows
# 1. Download and install MSYS2: https://www.msys2.org/. and open msys2 terminal
# 2. pacman -Syu
# 3. pacman -S git mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl mingw-w64-x86_64-libevent mingw-w64-x86_64-aclocal automake
# 4. Change to MSYS2 directory C:\msys64\home
# 5. ./autogen.sh
# 6. ./configure --enable-static-tor --disable-asciidoc --with-libevent-dir=/c/msys64/mingw64/lib --with-openssl-dir=/c/msys64/mingw64/lib --with-zlib-dir=/c/msys64/mingw64/lib LDFLAGS="-L/c/msys64/mingw64/lib" CFLAGS="-I/c/msys64/mingw64/include" 
# 7. make


# on mac
# brew install automake libevent openssl zlib
./autogen.sh
./configure --enable-static-libevent --enable-static-openssl --enable-static-zlib --disable-asciidoc --with-libevent-dir=/opt/homebrew/Cellar/libevent/2.1.12_1 --with-openssl-dir=/opt/homebrew/Cellar/openssl@3/3.3.1 --with-zlib-dir=/opt/homebrew/Cellar/zlib/1.3.1
make V=1

# copy tor binary to tor browser (on mac)
cp $HOME/code/tor/src/app/tor "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"
