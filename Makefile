

iproute2-src = iproute2-$(shell uname -r | cut -d '-' -f 1 | cut -d '.' -f 1,2).0
subdirs = kmod $(iproute2-src) test tools


all:
	for i in $(subdirs); do \
		echo; echo $$i; \
		make -C $$i; \
	done

install:
	for i in kmod $(iproute2-src) tools; do \
		echo; echo $$i; \
		make -C $$i install; \
	done

clean:
	for i in $(subdirs); do \
		echo; echo $$i; \
		make -C $$i clean; \
	done
