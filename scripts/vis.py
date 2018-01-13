import numpngw
import operator
import sys
import numpy

file = sys.argv[1]

file = open(file).read()
file = file.split("\n")

# make sure it's the right type of file
assert file[0].rstrip() == "TAINT DUMP"
file = file[1:-1]
def parse_line(i):
    i = i.rstrip().split(" ")
    assert i[0] == "APP" and \
           i[2] == "SHADOW"
    return int(i[1], 16), i[4]
mappings = map(parse_line, file)

for n,shadow in mappings:
    shadow = map(ord, shadow)
    shadow = numpy.asarray(shadow,
                dtype=numpy.uint8)
    shadow.resize(256, 64)

    numpngw.write_png("app_{:x}.png".format(n),
            shadow, bitdepth=1)
