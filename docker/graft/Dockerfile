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
	netperf		\
	netcat

	
# setup AF_GRAFT
RUN cd ${workdir}	\
	&& git clone --depth 1 https://github.com/upa/af-graft	\
	&& cd af-graft	\
	&& make		\
	&& make -C iproute2-4.10.0 install

ENV LD_PRELOAD ${workdir}/af-graft/tools/libgrwrap.so

ENTRYPOINT []
