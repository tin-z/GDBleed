import sys
from core.parser.objects import Section, Tag

from core.parser._constants import tags, sep_section, sep_sub_section ,\
                                    sect_skip_id, sect_declare_id, sect_code_id



def parse_blade(lines) :
  global tags
  sections = { k: Section(k.replace(sep_section,""), 0) for k in tags }

  prev_section = None
  section_now = None

  for i, line in enumerate(lines) :
    if line.startswith(sep_section) :
      for k in tags :
        if line.startswith(k) :
          prev_section = section_now
          section_now = sections[k]
          section_now.set_start(i)
          tag_list_now = tags[k]
          if prev_section :
            prev_section.set_end(i)
          break

    elif line.startswith(sep_sub_section):
      for k in tag_list_now :
        if line.startswith(k) :
          section_now.set_end_prev_tag(i)
          section_now.add_tag(Tag(k.replace(sep_sub_section,""), i))
          break

  if section_now :
    section_now.set_end(i)

  for sect in sections.values() :
    sect.set_data(lines)
    sect.update_line_number()

  return sections[sect_skip_id], sections[sect_declare_id], sections[sect_code_id]



if __name__ == "__main__" :
  import sys

  if len(sys.argv) < 2 :
    print("Usage: {} <source>".format(sys.argv[0]))
    sys.exit(1)

  file_path = sys.argv[-1]
  fp = open(file_path)
  lines = fp.read().split("\n")
  fp.close()
  print(parse_blade(lines))


