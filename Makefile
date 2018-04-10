all:
	mkdir -p build
	cd build && cmake .. -DDynamoRIO_DIR="$(DYNAMORIO_HOME)/cmake" -DDrMemoryFramework="$(DRMEMORY_HOME)" && make

install: all
	install -d /usr/local/lib/dynamorio
	install build/lib*.so /usr/local/lib/dynamorio
	#install drtaint.sh /usr/local/bin/

clean:
	rm -rf build
