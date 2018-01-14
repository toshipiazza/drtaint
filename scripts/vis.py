import numpngw
import operator
import sys
import numpy

file = sys.argv[1]

file = open(file).read()
file = file.split("\n")

def parse_line(i):
    i = i.rstrip().split(" ")
    assert i[0] == "APP" and \
           i[2] == "SHADOW"
    return int(i[1], 16), i[4]

# make sure it's the right type of file
assert file[0].rstrip() == "TAINT DUMP"
file = file[1:-1]
mappings = map(parse_line, file)

# consolidate mappings
mappings_ = [ mappings[0] ]
for curr in mappings[1:]:
    base, shadow = mappings_[-1]
    if base + len(shadow)*4 == curr[0]:
        shadow += curr[1]
        mappings_[-1] = (base, shadow)
    else:
        mappings_.append(curr)

# dump taint mappings to png's
for n,shadow in mappings_:
    shadow = map(ord, shadow)
    shadow = numpy.asarray(shadow,
                dtype=numpy.uint8)
    shadow.resize(len(shadow)/64, 64)
    numpngw.write_png("app_{:x}.png".format(n),
            shadow, bitdepth=1)
