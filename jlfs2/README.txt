This contains preliminary code for decoding JLFS2-based flash dumps. Nothing
useful yet, it simply decodes the file entries it finds. These flash dumps
are recognizable by having a string like "SH54" at offset 0x10.

Note that the algorithm uses heuristics to skip to the next file listing and to enter
directories. That algo is not very smart, causing some directories to be printed
in duplicate.
