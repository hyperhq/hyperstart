FROM ibmcom/centos:7
MAINTAINER Harshal Patil <harshal.patil@in.ibm.com>

RUN yum install -y patch gcc ncurses-devel make openssl-devel bc perl

ENV KERNEL_VERSION 4.12.4
ENV LOCALVERSION -hyper
ENV KERNEL_RELEASE ${KERNEL_VERSION}${LOCALVERSION}

ENV KBUILD_BUILD_USER    dev
ENV KBUILD_BUILD_HOST    hyper.sh
ENV KBUILD_BUILD_VERSION 1

RUN mkdir /root/build/ && mkdir /root/build/result/
RUN curl -fSL https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-${KERNEL_VERSION}.tar.gz | tar -zx -C /root/build

COPY kernel_config /root/build/linux-${KERNEL_VERSION}/.config
COPY kernel_patch/ /root/build/kernel_patch/

RUN cd /root/build/linux-${KERNEL_VERSION}/ && for patch in /root/build/kernel_patch/*.patch; do patch -p1 <$patch || exit 1; done
RUN cd /root/build/linux-${KERNEL_VERSION}/ && make silentoldconfig && make -j 8

# install to /root/build/result/ so that we can get them from it
RUN cp /root/build/linux-${KERNEL_VERSION}/vmlinux /root/build/result/kernel
RUN cp /root/build/linux-${KERNEL_VERSION}/.config /root/build/result/kernel_config
