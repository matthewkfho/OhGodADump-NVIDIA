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
