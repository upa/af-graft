

iproute2-src = iproute2-4.10.0

# XXX: check kernel version and switch iproute2-src to be compiled
#subdirs = kmod $(iproute2-src) test tools
subdirs = kmod test tools

all:
	for i in $(subdirs); do \
		echo; echo $$i; \
		make -C $$i; \
	done

clean:
	for i in $(subdirs); do \
		echo; echo $$i; \
		make -C $$i clean; \
	done
