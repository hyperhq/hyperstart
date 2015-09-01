# The init Task for Hyper

You can get the binary installer of Hyper and HyperStart through [The Hyper Page](https://github.com/hyperhq/hyper)

## Build from source 

clone this repo, and make sure you have build-essentials installed. Go into the working copy and

    > ./autogen.sh
    > ./configure
    > make

Then you can find `hyper-initrd.img` in the build directory, together with a pre-built kernel.

If you want to get the boot disk file for VirtualBox, please reconfigure with flag --with-vbox,

    > ./configure --with-vbox
    > make

Then you can find `hyper-vbox-bootimage.iso` in the build directory. Booting from this iso will
bring you to the hyper world.
