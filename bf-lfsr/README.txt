This is a tool that can crack the encryption on a flash dump and give you the XOR initialization
byte as well as the Galois LFSR initialization value and taps. Simply feed it with a
flash dump as an argument and let it go to work. Note that sometimes it spits out more than one
LFSR configuration: it could be that they're equivalent and either works, it could also be that 
they diverge later on. Simply try unpacking the flash dump with one and watch for CRC errors
while unpacking code.app; if you see that, try another one instead.
