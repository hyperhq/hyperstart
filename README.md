# The init Task for Hyper

You can get binary installer of Hyper and HyperStart through [The Hyper Page](https://github.com/hyperhq/hyper)

## Build from source 

clone this repo, and make sure have build-essentials installed. Go into the working copy and

    > ./autogen.sh
    > ./configure
    > make

Then you can find `hyper-initrd.img` in build directory, together with a pre-build kernel.
