from __future__              import print_function
from os                      import getenv
from sys                     import argv
from elftools.elf.elffile    import ELFFile
from elftools.elf.dynamic    import DynamicSection
from elftools.elf.relocation import RelocationSection
from operator                import itemgetter

with open(argv[1], 'r') as f:
    elf = ELFFile(f)
    sec = elf.get_section_by_name(".rel.dyn")
    if isinstance(sec, RelocationSection):
        dynrel = map(itemgetter('r_offset'), sec.iter_relocations())
        dynrel = map(str, dynrel)
        dynrel = ":".join(dynrel)
        print("-with_dynrel {}".format(dynrel))
    relro = False
    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    relro = True
    relro |= int(getenv("LD_BIND_NOW", "0")) == 1
    if relro:
        sec = elf.get_section_by_name(".rel.plt")
        if isinstance(sec, RelocationSection):
            pltrel = map(itemgetter('r_offset'), sec.iter_relocations())
            pltrel = map(str, pltrel)
            pltrel = ":".join(pltrel)
            print("-with_pltrel {}".format(pltrel))
