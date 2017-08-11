

iproute2-src = iproute2-4.10.0

subdirs = kmod $(iproute2-src) test

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
