### on linux
# sudo apt-get install automake libevent-dev zlib1g zlib1g-dev
# ./autogen.sh
# ./configure --disable-asciidoc

### windows
# 1. Download and install MSYS2: https://www.msys2.org/. and open msys2 terminal
# 2. pacman -Syu
# 3. pacman -S git mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl mingw-w64-x86_64-libevent mingw-w64-x86_64-aclocal automake
# 4. ./autogen.sh
# 5. ./configure --enable-static-tor --disable-asciidoc --with-libevent-dir=/c/msys64/mingw64/lib --with-openssl-dir=/c/msys64/mingw64/lib --with-zlib-dir=/c/msys64/mingw64/lib LDFLAGS="-L/c/msys64/mingw64/lib" CFLAGS="-I/c/msys64/mingw64/include" 
# 6. make


# on mac
# brew install automake libevent openssl zlib
LDFLAGS="-L/opt/homebrew/Cellar/libevent/2.1.12_1/lib -L/opt/homebrew/Cellar/openssl@3/3.3.1/lib -L/opt/homebrew/Cellar/zlib/1.3.1/lib"
./configure --disable-static --enable-shared \
    --with-libevent-dir=/opt/homebrew/opt/libevent \
    --with-openssl-dir=/opt/homebrew/opt/openssl@3 \
    --with-zlib-dir=/opt/homebrew/Cellar/zlib/1.3.1
make V=1
cp $HOME/code/tor/src/app/tor "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"
