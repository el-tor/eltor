make clean
./configure --with-libevent-dir=/opt/homebrew/Cellar/libevent/2.1.12_1 --with-openssl-dir=/opt/homebrew/Cellar/openssl@3/3.3.1 --disable-asciidoc
make
cp $HOME/code/tor/src/app/tor "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"
