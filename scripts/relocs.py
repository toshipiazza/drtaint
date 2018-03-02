from __future__              import print_function
from sys                     import argv
from elftools.elf.elffile    import ELFFile
from elftools.elf.relocation import RelocationSection
from operator                import itemgetter

with open(argv[1], 'r') as f:
    elf = ELFFile(f)
    sec = elf.get_section_by_name(".rel.dyn")
    if isinstance(sec, RelocationSection):
        dynrel = map(itemgetter('r_offset'), sec.iter_relocations())
        dynrel = map(str, dynrel)
        dynrel = ":".join(dynrel)
    sec = elf.get_section_by_name(".rel.plt")
    if isinstance(sec, RelocationSection):
        pltrel = map(itemgetter('r_offset'), sec.iter_relocations())
        pltrel = map(str, pltrel)
        pltrel = ":".join(pltrel)
print("-with_dynrel {} -with_pltrel {}".format(dynrel, pltrel))
