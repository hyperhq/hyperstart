# The init Task for HyperContainer

You can get the binary installer of HyperContainer and HyperStart through [The Hyper Page](https://github.com/hyperhq/hyperd)

## Build from source 

clone this repo, and make sure you have build-essential and autoconf installed. Go into the working copy and

    > ./autogen.sh
    > ./configure
    > make

Then you can find `hyper-initrd.img` in the build directory, together with a pre-built kernel.

If you want to run hyperstart with 64-bit ARM architecture, please reconfigure with flag --with-aarch64,

    > ./configure --with-aarch64
    > make
