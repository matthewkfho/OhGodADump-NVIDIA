|----INTRODUCTION----|

Welcome to OhGodADump - NVIDIA Edition!

OhGodADump takes any NVIDIA .ROM file - commonly used to program the VBIOS - and dumps the values, to either your terminal window or to a text file.

|----USEAGE----|

Windows PowerShell: .\nvbiosdump.exe <PathToROM> 
Windows CMD: nvbiosdump.exe <PathToROM>
Linux: ./nvbiosdump <PathToROM>

To push the results to a .txt file:

Windows PowerShell: .\nvbiosdump.exe ROMFile.bin > ROMFileDump.txt
Windows CMD: nvbiosdump.exe ROMFile.bin > ROMFileDump.txt
Linux: ./nvbiosdump ROMFile.bin > ROMFileDump.txt

|---SIGNING----|

Want to sign your VBIOS? Head on over to http://gfs.nvidia.com/, and roll your own signatures! Currently only works for mining cards; for others, you'll need to do a hardware flash. 

|---EDITING----|

OhGodADump comes with rudimentary reading and writing abilities - it outputs values to a JSON file, which can be modified, and fed back into a ROM.

A GUI is planned for 2018...sometime.
