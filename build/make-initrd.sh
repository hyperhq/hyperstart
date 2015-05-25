#!/bin/bash

rm -rf root
mkdir root

cp ../src/init ./root

ldd ./root/init | while read line
do
	arr=(${line// / })

	for lib in ${arr[@]}
	do
		if [ "${lib:0:1}" = "/" ]; then
			dir=root`dirname $lib`
			mkdir -p "${dir}"
			cp -f $lib $dir
		fi
	done
done
cd ./root && find . | cpio -H newc -o | gzip -9 > ../hyper-initrd.img
