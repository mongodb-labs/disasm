### UTILS ###
def print_all_sections(filename):
    print "Printing sections of", filename
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            print sec["sh_type"] + ", name: " + str(sec["sh_name"])

def print_iter(ob):
    for k, v in vars(ob).iteritems():
        print k, v
    print "\n"

def get_text_data(filename):
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        with open("../inputs/text_data", "w") as data:
            data.write(text.data())


