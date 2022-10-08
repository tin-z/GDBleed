#!/usr/bin/env python3
import re
maps_file = open("/proc/self/maps", 'r')
mem_file = open("/proc/self/mem", 'rb', 0)
output_file = open("self.dump", 'wb')
for line in maps_file.readlines():  # for each mapped region
    m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
    if m.group(3) == 'r':  # if this is a readable region
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        mem_file.seek(start)  # seek to region start

        try :
            chunk = mem_file.read(end - start)  # read region contents
        except OSError as ex:
            print(ex)
            print(f"Error on address/length {end:x} - {start:x}")
            break

        output_file.write(chunk)  # dump contents to standard output

maps_file.close()
mem_file.close()
output_file.close()

