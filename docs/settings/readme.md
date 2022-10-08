# Settings #


### './config.py' ###


 - `tmp_folder` : temporary folder used by gdbleed to save the current session
 
 - `log_file` : file where gdbleed currently save session (for now binary and libc location)
 
 - `ARCH_supported` : ARCH_supported
 
 - `compiler_path` : Cross-Compiler paths
 
 - `compiler_flags` : Cross-Compiler flags

 - `slog_path` : save output to 'slog_path' file (default: stdout)

---

### './gdbleed.py' ###


 - `details` : Dictionary passed through gdbleed classes containing data about the CPU architectures currently used

    * "capsize" : Size of pointers

    * "word" : format string for printable pointers in gdb using 'x' command notation

    * "arch" : arch currently used

    * "isa" : isa currently used

    * "running" : process is running

    * "slog" : slog class object

    * "endian" : endianess

    * "is_pie" : True if binary is PIE

    * "binary_path" : binary path
    
    * "libc_path" : libc path

    * "pid" : PID

    * "session_loaded" : True if session was loaded (TODO)

    * "qemu_usermode" : True if qemu user-mode is used



 - `details_mem` : Memory status info

    * "mm_regions" : Dict containing memory mapped by the process saved as `MemoryRegion` objects

    * "mm_addresses" : List containing LSB addresses of the memory mapped by the process

    * "mm_regions_ctrl" : Dict containing memory mapped by gdbleed commands saved as `MemoryRegion` objects

    * "mm_addresses_ctrl" : List containing LSB addresses of the memory mapped by gdbleed



 - `details_data` : Binary related info (GOT, sections, etc.)

    * "binary_name" : binary file name

    * "binary_name_local" : binary file name (the one saved in local)

    * "base_address" : base address given by the loader to the binary

    * "size_base_address" : size base address

    * "libc_base_address" : libc base address

    * "libc_size_base_address" : size libc base address

    * "got_entries" : GOT entries saved as `WrapPLTGOT` objects

    * "section_entries" : ELF sections saved as `WrapSection` objects

    * "parser" : `WrapParser` singleton object 
   
    * "compiler" : `Compiler` singleton object




