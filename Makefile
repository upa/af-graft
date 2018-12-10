

iproute2-src = iproute2-$(shell uname -r | cut -d '-' -f 1)
subdirs = kmod $(iproute2-src) test tools


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
