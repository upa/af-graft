FROM ubuntu:latest

ARG workdir="/root"

# install required packages and usuful applications
RUN apt-get update && apt-get install -y \
	git	\
	gcc	\
	make	\
	flex	\
	bison	\
	pkg-config	\
	vim	\
	iputils-ping	\
	net-tools	\
	iperf3		\
	netperf

	
# setup AF_GRAFT
RUN cd ${workdir}	\
	&& git clone https://github.com/upa/af-graft	\
	&& cd af-graft	\
	&& make

# overwrite /sbin/ip with af-graft ip
RUN cd ${workdir}	\
	&& cd af-graft/iproute2-4.10.0	\
	&& make install

ENV LD_PRELOAD ${workdir}/af-graft/tools/libgrwrap.so

ENTRYPOINT []
