#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <memory.h>		// for memchr()
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <jansson.h>

#include "nvbios.h"

#ifdef _WIN32
#define 	stat		_stat
#else
#include <unistd.h>
#endif

// Memory Clock Table pointer is in BIT_PERF_PTRS v2
// Format is segment:offset - (((uint16_t)segment) << 4) | ((uint16_t)offset)

int32_t GetPCIOptionROMOffset(const uint8_t *VBIOSImage, int VBIOSSize)
{
	// We know it's aligned on a 512 byte boundary
	for(int32_t i = 0; i < VBIOSSize; i += 0x200)
	{
		if(*((uint16_t *)(VBIOSImage + i)) == 0xAA55)
		{
			PCIRDataStructure *PCIR = (PCIRDataStructure *)(VBIOSImage + i + *((uint16_t *)(VBIOSImage + i + 0x18)));
			if(PCIR->Sig == PCIR_HEADER_SIGNATURE) return(i);
		}
	}
	
	return(-1);
}

#define GETPCIRHDROFFSET(VBIOSImg, OptionROMBase) ((OptionROMBase) + *((uint16_t *)((VBIOSImg) + (OptionROMBase) + 0x18)))

int32_t GetUEFIOptionROMImage(const uint8_t *VBIOSImage, int32_t PCIOptionROMListOffset)
{
	int32_t CurrentOptionROMHdr = PCIOptionROMListOffset;
	
	for(PCIRDataStructure *ROMPCIRHdr = (PCIRDataStructure *)(VBIOSImage + GETPCIRHDROFFSET(VBIOSImage, CurrentOptionROMHdr)); *((uint16_t *)(VBIOSImage + CurrentOptionROMHdr)) == 0xAA55 && ROMPCIRHdr->CodeType != 0x03; CurrentOptionROMHdr += (ROMPCIRHdr->ImageLength << 9), ROMPCIRHdr = ((PCIRDataStructure *)(VBIOSImage + GETPCIRHDROFFSET(VBIOSImage, CurrentOptionROMHdr))));
	
	return((*((uint16_t *)(VBIOSImage +  CurrentOptionROMHdr)) == 0xAA55) ? CurrentOptionROMHdr : -1);
}

// Returns -1 on failure
int32_t FindBITOffset(const uint8_t *VBIOSImage, int32_t ExpansionROMBase, int32_t VBIOSSize)
{
	// We do NOT know if the BIT is aligned!
	for(int i = ExpansionROMBase; i < (VBIOSSize - 6); ++i)
	{
		if((*((uint16_t *)(VBIOSImage + i)) == NV_BIT_HEADER_IDENTIFIER) && (*((uint32_t *)(VBIOSImage + i + 2)) == NV_BIT_HEADER_SIGNATURE))
			return(i);
	}
	
	return(-1);
}

// Returns -1 on failure
int FindBITToken(const BITHeader *BITHdr, uint8_t TokenID, uint8_t Version)
{
	BITToken *CurToken = (BITToken *)(((uint8_t *)BITHdr) + sizeof(BITHeader));
	
	for(int i = 0; i < BITHdr->TokenEntryCount; ++i)
	{
		if((CurToken[i].ID == TokenID) && (CurToken[i].DataVersion == Version))
			return(i);
	}
	
	return(-1);
}

void DumpBITToken(const uint8_t *VBIOSImage, const BITToken *Token)
{
	printf("\nToken ID: 0x%02X (\'%c\'); Token Version: 0x%02X\n", Token->ID, Token->ID, Token->DataVersion);
	printf("Token Size: 0x%04X; TokenOffset: 0x%04X\n", Token->DataSize, Token->DataOffset);
	
	if(Token->DataOffset)
	{
		const uint8_t *TokenData = VBIOSImage + Token->DataOffset;
		printf("\nToken Data:");
		
		for(int i = 0; i < Token->DataSize; ++i)
		{
			if(!(i & 15)) putchar('\n');
			printf("0x%02X ", TokenData[i]);
		}
	}
	else
	{
		printf("Token not present.");
	}
	
	putchar('\n');
}

// TODO/FIXME: Ensure ALL dumper functions check that the table
// version EXACTLY matches what they are expecting, and if not,
// failover to the default (generic) hex dumper.

void DumpBITI2CPtrs(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITI2CPtrs *I2CPtrs = (const BITI2CPtrs *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != '2') return;
	
	printf("\nI2C Scripts Pointer: 0x%04X\n", I2CPtrs->I2CScriptsPtr);
	printf("External HW Monitor Init Script Pointer: 0x%04X\n", I2CPtrs->ExtHWMonInitPtr);
}

void DumpBITBIOSDatav2(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITBIOSDatav2 *BIOSDatav2 = (const BITBIOSDatav2 *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'B') return;
	
	if(Token->DataVersion != 2)
	{
		printf("\nDecode of BIT_BIOSDATA v1 structure unsupported. Calling generic dumper.\n");
		DumpBITToken(VBIOSImage, Token);
		return;
	}
	
	printf("\nBIOS Version: 0x%08X\n", BIOSDatav2->BIOSVersion);
	printf("BIOS OEM Version: 0x%02X\n", BIOSDatav2->BIOSOEMVersion);
	printf("BIOS Checksum: 0x%02X\n", BIOSDatav2->BIOSChecksum);
	printf("INT15 POST Callbacks Pointer: 0x%04X\n", BIOSDatav2->Int15POSTCallbacks);
	printf("INT15 System Callbacks Pointer: 0x%04X\n", BIOSDatav2->Int15SystemCallbacks);
	printf("Frame count for SignOn Message: 0x%04X\n", BIOSDatav2->FrameCount);
	printf("Reserved: 0x%08X\n", BIOSDatav2->Reserved);
	printf("Max Heads at POST: 0x%02X\n", BIOSDatav2->MaxHeadsAtPOST);
	printf("Memory Size Report (MSR): 0x%02X\n", BIOSDatav2->MemorySizeReport);
	printf("Horizontal Scale Factor: 0x%02X\n", BIOSDatav2->HorizontalScaleFactor);
	printf("Vertical Scale Factor: 0x%02X\n", BIOSDatav2->VerticalScaleFactor);
	printf("Data Range Table Pointer: 0x%04X\n", BIOSDatav2->DataRangeTablePtr);
	printf("ROMpacks Pointer: 0x%04X\n", BIOSDatav2->ROMpacksPtr);
	printf("Applied ROMpacks Pointer: 0x%04X\n", BIOSDatav2->AppliedROMpacksPtr);
	printf("Applied ROMpacks Max: 0x%02X\n", BIOSDatav2->AppliedROMpacksMax);
	printf("Applied ROMpacks Count: 0x%02X\n", BIOSDatav2->AppliedROMpacksCount);
	printf("Module Map External 0: 0x%02X\n", BIOSDatav2->ModuleMapExternal0);
	printf("Compression Info Pointer: 0x%08X\n", BIOSDatav2->CompressionInfoPtr);
}

void DumpBITClockPtrs(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITClockPtrsv2 *ClkPtrs = (const BITClockPtrsv2 *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'C') return;
	
	if(Token->DataVersion != 2)
	{
		printf("\nDecode of BIT_CLOCK_PTRS v1 structure unsupported. Calling generic dumper.\n");
		DumpBITToken(VBIOSImage, Token);
		return;
	}
	
	printf("\nVBE Mode PCLK Table Pointer: 0x%08X\n", ClkPtrs->VBEModePCLKTblPtr);
	printf("Clocks Table Pointer: 0x%08X\n", ClkPtrs->ClocksTblPtr);
	printf("Clock Programming Table Pointer: 0x%08X\n", ClkPtrs->ClockProgrammingTblPtr);
	printf("NAFLL Table Pointer: 0x%0X\n", ClkPtrs->NAFLLTblPtr);
	printf("ADC Table Pointer: 0x%08X\n", ClkPtrs->ADCTblPtr);
	printf("Frequency Controller Table Pointer: 0x%08X\n", ClkPtrs->FreqControllerTblPtr);
}

void DumpBITDFPPtrs(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITDFPPtrs *DFPPtrs = (const BITDFPPtrs *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'D') return;
	
	printf("\nVESA Established Timing Tables Pointer: 0x%04X\n", DFPPtrs->VESAEstablishedTimingTblsPtr);
	printf("VBIOS-internal Flat Panel Tables Pointer: 0x%04X\n", DFPPtrs->VBIOSInternalFlatPanelTblsPtr);
}

void DumpBITNVInitPtrs(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITNVInitPtrs *NVInitPtrs = (const BITNVInitPtrs *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'I') return;
	
	printf("\nInit Script Table Pointer: 0x%04X\n", NVInitPtrs->InitScriptTblPtr);
	printf("Macro Index Table Pointer: 0x%04X\n", NVInitPtrs->MacroIndexTblPtr);
	printf("Macro Table Pointer: 0x%04X\n", NVInitPtrs->MacroTblPtr);
	printf("Condition Table Pointer: 0x%04X\n", NVInitPtrs->ConditionTblPtr);
	printf("I/O Condition Table Pointer: 0x%04X\n", NVInitPtrs->IOConditionTblPtr);
	printf("I/O Flag Condition Table Pointer: 0x%04X\n", NVInitPtrs->IOFlagConditionTblPtr);
	printf("Init Function Table Pointer: 0x%04X\n", NVInitPtrs->InitFunctionTblPtr);
	printf("VBIOS Private Boot Script Pointer: 0x%04X\n", NVInitPtrs->VBIOSPrivateBootScriptPtr);
	printf("Data Arrays Table Pointer: 0x%04X\n", NVInitPtrs->DataArraysTblPtr);
	printf("PCI-E Settings Script Pointer: 0x%04X\n", NVInitPtrs->PCIeSettingsScriptPtr);
	printf("Devinit Tables Pointer: 0x%04X\n", NVInitPtrs->DevinitTblsPtr);
	printf("Devinit Tables Size: 0x%04X\n", NVInitPtrs->DevinitTblsSize);
	printf("Boot Scripts Pointer: 0x%04X\n", NVInitPtrs->BootScriptsPtr);
	printf("Boot Scripts Size: 0x%04X\n", NVInitPtrs->BootScriptsSize);
	printf("Boot Scripts Non-GC6 Pointer: 0x%04X\n", NVInitPtrs->BootScriptsNonGC6Ptr);
	printf("Boot Scripts Non-GC6 Size: 0x%04X\n", NVInitPtrs->BootScriptsNonGC6Size);
}

void DumpBITMemoryPtrsv2(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITMemoryPtrsv2 *MemoryPtrs = (const BITMemoryPtrsv2 *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'M') return;
	
	printf("\nMemory Strap Data Count: 0x%02X\n", MemoryPtrs->MemoryStrapDataCount);
	printf("Memory Strap Translation Table Pointer: 0x%04X\n", MemoryPtrs->MemoryStrapTranslationTablePtr);
	printf("Memory Information Table Pointer: 0x%04X\n", MemoryPtrs->MemoryInformationTablePtr);
	printf("Memory Training Table Pointer: 0x%08X\n", MemoryPtrs->MemoryTrainingTablePtr);
	printf("Memory Training Pattern Table Pointer: 0x%08X\n", MemoryPtrs->MemoryTrainingPatternTablePtr);
	printf("Memory Partition Information Table: 0x%08X\n", MemoryPtrs->MemoryPartitionInformationTbl);
	printf("Memory Script List Pointer: 0x%08X\n", MemoryPtrs->MemoryScriptListPtr);
}

void DumpBITPerfPtrsv2(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITPerfPtrsv2 *PerfPtrs = (const BITPerfPtrsv2 *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'P') return;
	
	printf("\nPerformance Table Pointer: 0x%08X\n", PerfPtrs->PerformanceTblPtr);
	printf("Memory Clock Table Pointer: 0x%08X\n", PerfPtrs->MemoryClockTblPtr);
	printf("Memory Tweak Table Pointer: 0x%08X\n", PerfPtrs->MemoryTweakTblPtr);
	printf("Power Control Table Pointer: 0x%08X\n", PerfPtrs->PowerControlTblPtr);
	printf("Thermal Control Table Pointer: 0x%08X\n", PerfPtrs->ThermalControlTblPtr);
	printf("Thermal Device Table Pointer: 0x%08X\n", PerfPtrs->ThermalDeviceTblPtr);
	printf("Thermal Coolers Table Pointer: 0x%08X\n", PerfPtrs->ThermalCoolersTblPtr);
	printf("Performance Settings Script Pointer: 0x%08X\n", PerfPtrs->PerformanceSettingsScriptPtr);
	printf("Continuous Virtual Binning Table Pointer: 0x%08X\n", PerfPtrs->ContinuousVirtualBinningTblPtr);
	printf("Ventura Table Pointer: 0x%08X\n", PerfPtrs->VenturaTblPtr);
	printf("Power Sensors Table Pointer: 0x%08X\n", PerfPtrs->PowerSensorsTblPtr);
	printf("Power Capping Table Pointer: 0x%08X\n", PerfPtrs->PowerCappingTblPtr);
	printf("P-State Clock Range Table Pointer: 0x%08X\n", PerfPtrs->PStateClockRangeTblPtr);
	printf("Voltage Frequency Table Pointer: 0x%08X\n", PerfPtrs->VoltageFrequencyTblPtr);
	printf("Virtual P-State Table Pointer: 0x%08X\n", PerfPtrs->VirtualPStateTblPtr);
	printf("Power Topology Table Pointer: 0x%08X\n", PerfPtrs->PowerTopologyTblPtr);
	printf("Power Leakage Table Pointer: 0x%08X\n", PerfPtrs->PowerLeakageTblPtr);
	printf("Performance Test Specifications Table Pointer: 0x%08X\n", PerfPtrs->PerformanceTestSpecificationsTblPtr);
	printf("Thermal Channel Table Pointer: 0x%08X\n", PerfPtrs->ThermalChannelTblPtr);
	printf("Thermal Adjustment Table Pointer: 0x%08X\n", PerfPtrs->ThermalAdjustmentTblPtr);
	printf("Thermal Policy Table Pointer: 0x%08X\n", PerfPtrs->ThermalPolicyTblPtr);
	printf("P-State Memory Clock Frequency Table Pointer: 0x%08X\n", PerfPtrs->PStateMemoryClockFrequencyTblPtr);
	printf("Fan Cooler Table Pointer: 0x%08X\n", PerfPtrs->FanCoolerTblPtr);
	printf("Fan Policy Table Pointer: 0x%08X\n", PerfPtrs->FanPolicyTblPtr);
	printf("DI/DT Table Pointer: 0x%08X\n", PerfPtrs->DIDTTblPtr);
	printf("Fan Test Table Pointer: 0x%08X\n", PerfPtrs->FanTestTblPtr);
	printf("Voltage Rail Table Pointer: 0x%08X\n", PerfPtrs->VoltageRailTblPtr);
	printf("Voltage Device Table Pointer: 0x%08X\n", PerfPtrs->VoltageDeviceTblPtr);
	printf("Voltage Policy Table Pointer: 0x%08X\n", PerfPtrs->VoltagePolicyTblPtr);
	printf("LowPower Table Pointer: 0x%08X\n", PerfPtrs->LowPowerTblPtr);
	printf("LowPower PCIe Table Pointer: 0x%08X\n", PerfPtrs->LowPowerPCIeTblPtr);
	printf("LowPower PCIe-Platform Table Pointer: 0x%08X\n", PerfPtrs->LowPowerPCIePlatformTblPtr);
	printf("LowPower GR Table Pointer: 0x%08X\n", PerfPtrs->LowPowerGRTblPtr);
	printf("LowPower MS Table Pointer: 0x%08X\n", PerfPtrs->LowPowerMSTblPtr);
	printf("LowPower DI Table Pointer: 0x%08X\n", PerfPtrs->LowPowerDITblPtr);
	printf("LowPower GC6 Table Pointer: 0x%08X\n", PerfPtrs->LowPowerGC6TblPtr);
	printf("LowPower PSI Table Pointer: 0x%08X\n", PerfPtrs->LowPowerPSITblPtr);
	printf("Thermal Monitor Table Pointer: 0x%08X\n", PerfPtrs->ThermalMonitorTblPtr);
	printf("Overclocking Table Pointer: 0x%08X\n", PerfPtrs->OverclockingTblPtr);
	printf("LowPower NVLINK Table Pointer: 0x%08X\n", PerfPtrs->LowPowerNVLINKTblPtr);
}

void DumpBITStringPtrsv2(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITStringPtrsv2 *StringPtrs = (const BITStringPtrsv2 *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'S') return;
	
	printf("\nSign On Message Offset: 0x%04X - maximum length: %d.\n", StringPtrs->SignOnMsgPtr, StringPtrs->SignOnMsgMaxLen);
	printf("Version Message Offset: 0x%04X - maximum length: %d\n", StringPtrs->VersionMsgPtr, StringPtrs->VersionMsgMaxLen);
	printf("Copyright Message Offset: 0x%04X - maximum length: %d\n", StringPtrs->CopyrightMsgPtr, StringPtrs->CopyrightMsgMaxLen);
	printf("OEM Message Offset: 0x%04X - maximum length: %d\n", StringPtrs->OEMMsgPtr, StringPtrs->OEMMsgMaxLen);
	printf("OEM Vendor Name Offset: 0x%04X - maximum length: %d\n", StringPtrs->OEMVendorNameMsgPtr, StringPtrs->OEMVendorNameMsgMaxLen);
	printf("OEM Product Name Offset: 0x%04X - maximum length: %d\n", StringPtrs->OEMProductNameMsgPtr, StringPtrs->OEMProductNameMsgMaxLen);
	printf("OEM Product Revision Offset: 0x%04X - maximum length: %d\n", StringPtrs->OEMProductRevisionMsgPtr, StringPtrs->OEMProductRevisionMsgMaxLen);
}

void DumpBITTMDSPtrs(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITTMDSPtrs *TMDSPtrs = (const BITTMDSPtrs *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'T') return;
	
	printf("\nTMDS Info Table Pointer: 0x%04X\n", TMDSPtrs->TMDSInfoTblPtr);
}

void DumpBITDisplayPtrs(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITDisplayPtrs *DisplayPtrs = (const BITDisplayPtrs *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'U') return;
	
	printf("\nDisplay Scripting Table Pointer: 0x%04X\n", DisplayPtrs->DisplayScriptingTblPtr);
	printf("Display Control Flags: 0x%02X\n", DisplayPtrs->DisplayControlFlags);
	printf("SLI Table Header Pointer: 0x%04X\n", DisplayPtrs->SLITblHdrPtr);
}

void DumpBITVirtualPtrs(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITVirtualPtrs *VirtualPtrs = (const BITVirtualPtrs *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'V') return;
	
	printf("\nVirtual Strap Field Table Pointer: 0x%04X\n", VirtualPtrs->VirtualStrapFieldTblPtr);
	printf("Virtual Strap Field Register: 0x%04X\n", VirtualPtrs->VirtualStrapFieldRegister);
	printf("Translation Table Pointer: 0x%04X\n", VirtualPtrs->TranslationTblPtr);
}

void DumpBITMXMData(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITMXMData *MXMData = (const BITMXMData *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'x') return;
	
	printf("\nModule Spec Version: 0x%02X\n", MXMData->ModuleSpecVersion);
	printf("Module Flags 0: 0x%02X\n", MXMData->ModuleFlags0);
	printf("Config Flags 0: 0x%02X\n", MXMData->ConfigFlags0);
	printf("DP Drive Strength Scale: 0x%02X\n", MXMData->DPDriveStrengthScale);
	printf("MXM Digital Connector Table Pointer: 0x%04X\n", MXMData->MXMDigitalConnectorTblPtr);
	printf("MXM DDC/Aux to CCB Table Pointer: 0x%04X\n", MXMData->MXMDDCAuxToCCBTblPtr);
}

void DumpBITDPPtrs(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITDPPtrs *DPPtrs = (const BITDPPtrs *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'd') return;
	
	printf("\nDP Info Table Pointer: 0x%04X\n", DPPtrs->DPInfoTblPtr);
}

void DumpBITFalconData(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITFalconDatav2 *FalconData = (const BITFalconDatav2 *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'p') return;
	
	if(Token->DataVersion != 2)
	{
		printf("\nDecode of BIT_PMU_PTRS v1 structure unsupported. Calling generic dumper.\n");
		DumpBITToken(VBIOSImage, Token);
		return;
	}
	
	printf("\nFalcon Ucode Table Pointer: 0x%08X\n", FalconData->FalconUcodeTblPtr);
}

void DumpBITUEFIData(const uint8_t *VBIOSImage, const BITToken *Token)
{
	const BITUEFIData *UEFIData = (const BITUEFIData *)(VBIOSImage + Token->DataOffset);
	
	if(Token->ID != 'u') return;
	
	printf("\nMinimum UEFI Driver Version: 0x%08X\n", UEFIData->MinimumUEFIDriverVersion);
	printf("UEFI Compatibility Level: 0x%02X\n", UEFIData->UEFICompatibilityLevel);
	printf("UEFI Flags: 0x%016llX\n", UEFIData->UEFIFlags);
}

void DumpMemoryClockTable(const NVMemoryClockTableHdr *ClockTbl)
{
	uint32_t TableSize = ClockTbl->BaseEntrySize + (sizeof(NVMemoryClockTableStrapEntry) * ClockTbl->StrapEntryCount);
	
	printf("\nMemory Clock Table Header:\n");
	printf("\tVersion: 0x%02X\n", ClockTbl->Version);
	printf("\tHeader Size: 0x%02X\n", ClockTbl->HeaderSize);
	printf("\tBase Entry Size: 0x%02X\n", ClockTbl->BaseEntrySize);
	printf("\tStrap Entry Size: 0x%02X\n", ClockTbl->StrapEntrySize);
	printf("\tStrap Entry Count: 0x%02X\n", ClockTbl->StrapEntryCount);
	printf("\tEntry Count: 0x%02X\n", ClockTbl->EntryCount);
	
	NVMemoryClockTableBaseEntry *MemClkTblBaseEntry = (NVMemoryClockTableBaseEntry *)(((uint8_t *)ClockTbl) + sizeof(NVMemoryClockTableHdr));
	
	printf("\nMemory Clock Table Base Entry:\n");
	printf("\tMinFreq: 0x%04X\n", MemClkTblBaseEntry->MinFreq);
	printf("\t\tMinFrequency: 0x%04X\n", MemClkTblBaseEntry->MinFreq.MinFrequency);
	printf("\tMaxFreq: 0x%04X\n", MemClkTblBaseEntry->MaxFreq);
	printf("\t\tMaxFrequency: 0x%04X\n", MemClkTblBaseEntry->MaxFreq.MaxFrequency);
	printf("\tReserved0: 0x%08X\n", MemClkTblBaseEntry->Reserved0);
	printf("\tFlags0: 0x%08X\n", MemClkTblBaseEntry->Flags0);
	printf("\t\tGear Shift: 0x%02X\n", MemClkTblBaseEntry->Flags0.GearShift);
	printf("\t\tExtended QUSE: 0x%02X\n", MemClkTblBaseEntry->Flags0.ExtendedQUSE);
	printf("\t\tSDM: 0x%02X\n", MemClkTblBaseEntry->Flags0.SDM);
	printf("\tReadWriteConfig0: 0x%08X\n", MemClkTblBaseEntry->ReadWriteConfig0);
	printf("\t\tReadSettings0: 0x%04X\n", MemClkTblBaseEntry->ReadWriteConfig0.ReadSettings0);
	printf("\t\tWriteSettings0: 0x%04X\n", MemClkTblBaseEntry->ReadWriteConfig0.WriteSettings0);
	printf("\t\tReadSettings1: 0x%02X\n", MemClkTblBaseEntry->ReadWriteConfig0.ReadSettings1);
	printf("\tReadWriteConfig1: 0x%08X\n", MemClkTblBaseEntry->ReadWriteConfig1);
	printf("\t\tReadSettings0: 0x%01X\n", MemClkTblBaseEntry->ReadWriteConfig1.ReadSettings0);
	printf("\t\tWriteSettings0: 0x%01X\n", MemClkTblBaseEntry->ReadWriteConfig1.WriteSettings0);
	printf("\t\tReadSettings1: 0x%01X\n", MemClkTblBaseEntry->ReadWriteConfig1.ReadSettings1);
	printf("\t\tWriteSettings1: 0x%01X\n", MemClkTblBaseEntry->ReadWriteConfig1.WriteSettings1);
	printf("\t\tReadSettings2: 0x%01X\n", MemClkTblBaseEntry->ReadWriteConfig1.ReadSettings2);
	printf("\t\tWriteSettings2: 0x%01X\n", MemClkTblBaseEntry->ReadWriteConfig1.WriteSettings2);
	printf("\t\tTimingSettings0: 0x%02X\n", MemClkTblBaseEntry->ReadWriteConfig1.TimingSettings0);
	printf("\tReserved1: 0x%02X\n", MemClkTblBaseEntry->Reserved1);
	printf("\tReserved2: 0x%04X\n", MemClkTblBaseEntry->Reserved2);
	
	for(int i = 0; i < ClockTbl->StrapEntryCount; ++i)
	{
		NVMemoryClockTableStrapEntry *CurrentStrapEntry = (NVMemoryClockTableStrapEntry *)(((uint8_t *)ClockTbl) + sizeof(NVMemoryClockTableHdr) + sizeof(NVMemoryClockTableBaseEntry) + (sizeof(NVMemoryClockTableStrapEntry) * i));
		
		printf("\nMemory Clock Table Strap Entry %d:\n", i);
		printf("\tFlags0: 0x%02X\n", CurrentStrapEntry->Flags0);
		printf("\t\tAlignment Mode: 0x%01X\n", CurrentStrapEntry->Flags0.AlignmentMode);
		printf("\tFlags1: 0x%02X\n", CurrentStrapEntry->Flags1);
		printf("\t\tConfig5 VDDP Mode: 0x%01X\n", CurrentStrapEntry->Flags1.Config5VDDPMode);
		printf("\t\tFBVDDQ Voltage: 0x%01X\n", CurrentStrapEntry->Flags1.FBVDDQVoltage);
		printf("\t\tGDDR5FB VREF: 0x%01X\n", CurrentStrapEntry->Flags1.GDDR5FBVREF);
		printf("\t\tMemory VREFD: 0x%01X\n", CurrentStrapEntry->Flags1.MemoryVREFD);
		printf("\tReserved0: 0x%02X%02X%02X%02X%02X\n", CurrentStrapEntry->Reserved0[0], CurrentStrapEntry->Reserved0[0], CurrentStrapEntry->Reserved0[1], CurrentStrapEntry->Reserved0[2], CurrentStrapEntry->Reserved0[3], CurrentStrapEntry->Reserved0[4]);
		printf("\tFlags4: 0x%02X\n", CurrentStrapEntry->Flags4);
		printf("\t\tMRS7 GDDR5: 0x%01X\n", CurrentStrapEntry->Flags4.MRS7GDDR5);
		printf("\tReserved1: 0x%02X\n", CurrentStrapEntry->Reserved1);
		printf("\tFlags5: 0x%02X\n", CurrentStrapEntry->Flags5);
		printf("\t\tGDDR5X MR8: 0x%01X\n", CurrentStrapEntry->Flags5.GDDR5XMR8);
		printf("\t\tGDDR5X Internal VREFC: 0x%01X\n", CurrentStrapEntry->Flags5.GDDR5XInternalVREFC);
		printf("\tGDDR5XMicronMSR34Offset: 0x%02X\n", CurrentStrapEntry->GDDR5XMicronMSR14Offset);
		printf("\t\tMRS14 Micron Core Voltage: 0x%02X\n", CurrentStrapEntry->GDDR5XMicronMSR14Offset.MRS14MicronCoreVoltage);
		printf("\t\tMRS14 GDDR5X Subregister Select: 0x%01X\n", CurrentStrapEntry->GDDR5XMicronMSR14Offset.MRS14GDDR5XSubregisterSelect);
		printf("\tReserved2: ");
		
		for(int x = 0; x < 14; ++x) printf("%02X", CurrentStrapEntry->Reserved2[13 - x]);
		
		putchar('\n');
	}
}

void DumpMemoryTweakTable(const NVMemoryTweakTableHdr *TweakTbl)
{
	printf("\nMemory Tweak Table:\n");
	printf("\tVersion: 0x%02X\n", TweakTbl->Version);
	printf("\tHeader Size: 0x%02X\n", TweakTbl->HeaderSize);
	printf("\tBase Entry Size: 0x%02X\n", TweakTbl->BaseEntrySize);
	printf("\tExtended Entry Size: 0x%02X\n", TweakTbl->ExtendedEntrySize);
	printf("\tExtended Entry Count: 0x%02X\n", TweakTbl->ExtendedEntryCount);
	printf("\tEntry Count: 0x%02X\n", TweakTbl->EntryCount);
	
	NVMemoryTweakTableBaseEntry *MemTweakTblBaseEntry = (NVMemoryTweakTableBaseEntry *)(((uint8_t *)TweakTbl) + sizeof(NVMemoryTweakTableHdr));
	
	printf("\nMemory Tweak Table Base Entry:\n");
	printf("\tCONFIG0: 0x%08X\n", MemTweakTblBaseEntry->CONFIG0);
	printf("\t\tRC: 0x%02X\n", MemTweakTblBaseEntry->CONFIG0.RC);
	printf("\t\tRFC: 0x%03X\n", MemTweakTblBaseEntry->CONFIG0.RFC);
	printf("\t\tRAS: 0x%02X\n", MemTweakTblBaseEntry->CONFIG0.RAS);
	printf("\t\tRP: 0x%02X\n", MemTweakTblBaseEntry->CONFIG0.RP);
	printf("\tCONFIG1: 0x%08X\n", MemTweakTblBaseEntry->CONFIG1);
	printf("\t\tCL: 0x%02X\n", MemTweakTblBaseEntry->CONFIG1.CL);
	printf("\t\tWL: 0x%02X\n", MemTweakTblBaseEntry->CONFIG1.WL);
	printf("\t\tRD_RCD: 0x%02X\n", MemTweakTblBaseEntry->CONFIG1.RD_RCD);
	printf("\t\tWR_RCD: 0x%02X\n", MemTweakTblBaseEntry->CONFIG1.WR_RCD);
	printf("\tCONFIG2: 0x%08X\n", MemTweakTblBaseEntry->CONFIG2);
	printf("\t\tRPRE: 0x%01X\n", MemTweakTblBaseEntry->CONFIG2.RPRE);
	printf("\t\tWPRE: 0x%01X\n", MemTweakTblBaseEntry->CONFIG2.WPRE);
	printf("\t\tCDLR: 0x%02X\n", MemTweakTblBaseEntry->CONFIG2.CDLR);
	printf("\t\tWR: 0x%02X\n", MemTweakTblBaseEntry->CONFIG2.WR);
	printf("\t\tW2R_BUS: 0x%01X\n", MemTweakTblBaseEntry->CONFIG2.W2R_BUS);
	printf("\t\tR2W_BUS: 0x%01X\n", MemTweakTblBaseEntry->CONFIG2.R2W_BUS);
	printf("\tCONFIG3: 0x%08X\n", MemTweakTblBaseEntry->CONFIG3);
	printf("\t\tPDEX: 0x%02X\n", MemTweakTblBaseEntry->CONFIG3.PDEX);
	printf("\t\tPDEN2PDEX: 0x%01X\n", MemTweakTblBaseEntry->CONFIG3.PDEN2PDEX);
	printf("\t\tFAW: 0x%02X\n", MemTweakTblBaseEntry->CONFIG3.FAW);
	printf("\t\tAOND: 0x%02X\n", MemTweakTblBaseEntry->CONFIG3.AOND);
	printf("\t\tCCDL: 0x%01X\n", MemTweakTblBaseEntry->CONFIG3.CCDL);
	printf("\t\tCCDS: 0x%01X\n", MemTweakTblBaseEntry->CONFIG3.CCDS);
	printf("\tCONFIG4: 0x%08X\n", MemTweakTblBaseEntry->CONFIG4);
	printf("\t\tREFRESH_LO: 0x%01X\n", MemTweakTblBaseEntry->CONFIG4.REFRESH_LO);
	printf("\t\tREFRESHL 0x%03X\n", MemTweakTblBaseEntry->CONFIG4.REFRESH);
	printf("\t\tRRD: 0x%02X\n", MemTweakTblBaseEntry->CONFIG4.RRD);
	printf("\t\tDELAY0: 0x%02X\n", MemTweakTblBaseEntry->CONFIG4.DELAY0);
	printf("\tCONFIG5: 0x%08X\n", MemTweakTblBaseEntry->CONFIG5);
	printf("\t\tADR_MIN: 0x%01X\n", MemTweakTblBaseEntry->CONFIG5.ADR_MIN);
	printf("\t\tWRCRC: 0x%02X\n", MemTweakTblBaseEntry->CONFIG5.WRCRC);
	printf("\t\tOFFSET0: 0x%02X\n", MemTweakTblBaseEntry->CONFIG5.OFFSET0);
	printf("\t\tINTRP_MSB: 0x%01X\n", MemTweakTblBaseEntry->CONFIG5.INTRP_MSB);
	printf("\t\tOFFSET1: 0x%02X\n", MemTweakTblBaseEntry->CONFIG5.OFFSET1);
	printf("\t\tOFFSET2: 0x%02X\n", MemTweakTblBaseEntry->CONFIG5.OFFSET2);
	printf("\t\tINTRP: 0x%02X\n", MemTweakTblBaseEntry->CONFIG5.INTRP);
	printf("\tMISCSHIT: 0x%08X\n", MemTweakTblBaseEntry->MISCSHIT);
	printf("\t\tDrive Strength: 0x%01X\n", MemTweakTblBaseEntry->MISCSHIT.DriveStrength);
	printf("\t\tVoltage0: 0x%01X\n", MemTweakTblBaseEntry->MISCSHIT.Voltage0);
	printf("\t\tVoltage1: 0x%01X\n", MemTweakTblBaseEntry->MISCSHIT.Voltage1);
	printf("\t\tVoltage2: 0x%01X\n", MemTweakTblBaseEntry->MISCSHIT.Voltage2);
	printf("\t\tR2P: 0x%02X\n", MemTweakTblBaseEntry->MISCSHIT.R2P);
	printf("\t\tVoltage3: 0x%01X\n", MemTweakTblBaseEntry->MISCSHIT.Voltage3);
	printf("\t\tVoltage4: 0x%01X\n", MemTweakTblBaseEntry->MISCSHIT.Voltage4);
	printf("\t\tVoltage5: 0x%01X\n", MemTweakTblBaseEntry->MISCSHIT.Voltage5);
	printf("\tRDCRC: 0x%01X\n", MemTweakTblBaseEntry->RDCRC);
	printf("\tTIMING22: 0x%08X\n", MemTweakTblBaseEntry->TIMING22);
	printf("\t\tRFCSBA: 0x%03X\n", MemTweakTblBaseEntry->TIMING22.RFCSBA);
	printf("\t\tRFCSBR: 0x%02X\n", MemTweakTblBaseEntry->TIMING22.RFCSBR);
}

uint32_t amd_bfe(uint32_t s0, uint32_t s1, uint32_t s2)
{
	uint32_t offset = s1 & 0x1F, width = s2 & 0x1F;
	
	if(!width) return(0);
	else if((offset + width) < 32) return((s0 << (32 - offset - width)) >> (32 - width));
	else return(s0 >> offset);
}

// String validity check is caller's responsibility
// Length checking is performed by the callee, though
// The offset MUST 31 or less, the bitsize MUST be 32 or less.
uint32_t ASCIIHexToDword(const char *restrict asciistr, uint32_t offset, uint32_t bitsize)
{
	int len = strlen(asciistr);
	uint32_t num;
	
	if((bitsize > 32) || (offset > 31)) return(0UL);
	
	if(asciistr[0] == '0' && asciistr[1] == 'x')
	{
		asciistr += 2;
		len -= 2;
	}
	
	if(len > 8) return(0UL);
	
	num = strtoul(asciistr, NULL, 16);
	return(amd_bfe(num, offset, bitsize));
}

void DwordToASCIIHex(char *restrict asciistr, const void *dword, uint8_t size)
{
	int pad = 2;
	asciistr[0] = '0';
	asciistr[1] = 'x';
	
	if(size < 4) pad += (4 - size) << 1;
	
	for(int i = 2; i < pad; ++i) asciistr[i] = '0';
	
	for(int i = 0, j = 8; i < size; ++i, j -= 2)
	{
		asciistr[j] = "0123456789ABCDEF"[((uint8_t *)dword)[i] >> 4];
		asciistr[j + 1] = "0123456789ABCDEF"[((uint8_t *)dword)[i] & 0x0F];
	}
	
	asciistr[10] = 0x00;
}

json_t *DumpMemoryClockTableAsJSON(const NVMemoryClockTableHdr *ClockTbl)
{
	uint32_t TableSize = ClockTbl->BaseEntrySize + (ClockTbl->StrapEntrySize * ClockTbl->StrapEntryCount);
	json_t *JSONMemClkTblObj, *JSONHeaderObj, *JSONBaseEntryObj, *JSONStrapArray;
	char tmpstrs[6][11];
	
	DwordToASCIIHex(tmpstrs[0], &ClockTbl->Version, 1);
	DwordToASCIIHex(tmpstrs[1], &ClockTbl->HeaderSize, 1);
	DwordToASCIIHex(tmpstrs[2], &ClockTbl->BaseEntrySize, 1);
	DwordToASCIIHex(tmpstrs[3], &ClockTbl->StrapEntrySize, 1);
	DwordToASCIIHex(tmpstrs[4], &ClockTbl->StrapEntryCount, 1);
	DwordToASCIIHex(tmpstrs[5], &ClockTbl->EntryCount, 1);
	
	JSONHeaderObj = json_pack("{ssssssssssss}", "Version", tmpstrs[0], "HeaderSize", tmpstrs[1], "BaseEntrySize", tmpstrs[2], "StrapEntrySize", tmpstrs[3], \
		"StrapEntryCount", tmpstrs[4], "EntryCount", tmpstrs[5]);
		
	NVMemoryClockTableBaseEntry *MemClkTblBaseEntry = (NVMemoryClockTableBaseEntry *)(((uint8_t *)ClockTbl) + sizeof(NVMemoryClockTableHdr));
	
	DwordToASCIIHex(tmpstrs[0], &MemClkTblBaseEntry->MinFreq, 2);
	DwordToASCIIHex(tmpstrs[1], &MemClkTblBaseEntry->MaxFreq, 2);
	DwordToASCIIHex(tmpstrs[2], &MemClkTblBaseEntry->Flags0, 1);
	DwordToASCIIHex(tmpstrs[3], &MemClkTblBaseEntry->ReadWriteConfig0, 4);
	DwordToASCIIHex(tmpstrs[4], &MemClkTblBaseEntry->ReadWriteConfig1, 4);
	
	JSONBaseEntryObj = json_pack("{ssssssssss}", "MinFreq", tmpstrs[0], "MaxFreq", tmpstrs[1], "Flags0", tmpstrs[2], \
		"ReadWriteConfig0", tmpstrs[3], "ReadWriteConfig1", tmpstrs[4]);
		
	JSONStrapArray = json_array();
	
	for(int i = 0; i < ClockTbl->StrapEntryCount; ++i)
	{
		NVMemoryClockTableStrapEntry *CurrentStrapEntry = (NVMemoryClockTableStrapEntry *)(((uint8_t *)ClockTbl) + sizeof(NVMemoryClockTableHdr) + sizeof(NVMemoryClockTableBaseEntry) + (sizeof(NVMemoryClockTableStrapEntry) * i));
		json_t *JSONStrapEntry;
		
		DwordToASCIIHex(tmpstrs[0], &CurrentStrapEntry->MemTweakIndex, 1);
		DwordToASCIIHex(tmpstrs[1], &CurrentStrapEntry->Flags0, 1);
		DwordToASCIIHex(tmpstrs[2], &CurrentStrapEntry->Flags1, 1);
		DwordToASCIIHex(tmpstrs[3], &CurrentStrapEntry->Flags4, 1);
		DwordToASCIIHex(tmpstrs[4], &CurrentStrapEntry->Flags5, 1);
		DwordToASCIIHex(tmpstrs[5], &CurrentStrapEntry->GDDR5XMicronMSR14Offset, 1);
		
		JSONStrapEntry = json_pack("{ssssssssssss}", "MemTweakIndex", tmpstrs[0], "Flags0", tmpstrs[1], "Flags1", tmpstrs[2], "Flags4", tmpstrs[3], "Flags5", tmpstrs[4], \
			"GDDR5XMicronMSR1Offset", tmpstrs[5]);
		
		json_array_append_new(JSONStrapArray, JSONStrapEntry);
		
	}
	
	JSONMemClkTblObj = json_pack("{sososo}", "Header", JSONHeaderObj, "Base Entry", JSONBaseEntryObj, "Strap Entries", JSONStrapArray);
		
	//printf("DBG:\n%s\n", json_dumps(JSONMemClkTblObj, JSON_INDENT(4)));
	return(JSONMemClkTblObj);
}

uint32_t BuildMemoryClockTable(json_t *JSONMemClkTblObj, void **NewClkTbl)
{
	json_t *JSONHeaderObj, *JSONBaseEntryObj, *JSONStrapArray;
	NVMemoryClockTableStrapEntry *CurStrapEntry;
	NVMemoryClockTableBaseEntry BaseEntry;
	uint32_t TmpDwords[6], TableSize, pos;
	NVMemoryClockTableHdr Hdr;
	char *TmpStrs[6];
	int ret;
	
	// If we return without having allocated memory for the new table (and, of course, populating it)
	// then it was certainly due to an error condition - so may as well set it as such just once here.
	*NewClkTbl = NULL;
	
	JSONHeaderObj = json_object_get(JSONMemClkTblObj, "Header");
	
	if(!JSONHeaderObj) return(0);
		
	ret = json_unpack_ex(JSONHeaderObj, NULL, JSON_STRICT, "{ssssssssssss}", "Version", &TmpStrs[0], "HeaderSize", &TmpStrs[1], "BaseEntrySize", &TmpStrs[2], "StrapEntrySize", &TmpStrs[3], \
		"StrapEntryCount", &TmpStrs[4], "EntryCount", &TmpStrs[5]);
	
	if(ret == -1) return(0);
	
	Hdr.Version = ASCIIHexToDword(TmpStrs[0], 0UL, 8UL);
	Hdr.HeaderSize = ASCIIHexToDword(TmpStrs[1], 8UL, 8UL);
	Hdr.BaseEntrySize = ASCIIHexToDword(TmpStrs[2], 16UL, 8UL);
	Hdr.StrapEntrySize = ASCIIHexToDword(TmpStrs[3], 24UL, 8UL);
	Hdr.StrapEntryCount = ASCIIHexToDword(TmpStrs[4], 0UL, 8UL);
	Hdr.EntryCount = ASCIIHexToDword(TmpStrs[5], 8UL, 8UL);
	
	TableSize = sizeof(NVMemoryClockTableHdr) + Hdr.BaseEntrySize + (sizeof(NVMemoryClockTableStrapEntry) * (Hdr.StrapEntryCount + 1));
	
	JSONBaseEntryObj = json_object_get(JSONMemClkTblObj, "Base Entry");
	
	if(!JSONBaseEntryObj) return(0);
	
	ret = json_unpack_ex(JSONBaseEntryObj, NULL, JSON_STRICT, "{ssssssssss}", "MinFreq", &TmpStrs[0], "MaxFreq", &TmpStrs[1], "Flags0", &TmpStrs[2], \
		"ReadWriteConfig0", &TmpStrs[3], "ReadWriteConfig1", &TmpStrs[4]);
		
	*((uint32_t *)(&BaseEntry.MinFreq)) = ASCIIHexToDword(TmpStrs[0], 0UL, 16UL);
	*((uint32_t *)(&BaseEntry.MaxFreq)) = ASCIIHexToDword(TmpStrs[1], 16UL, 16UL);
	*((uint32_t *)(&BaseEntry.Flags0)) = ASCIIHexToDword(TmpStrs[2], 0UL, 8UL);
	*((uint32_t *)(&BaseEntry.ReadWriteConfig0)) = ASCIIHexToDword(TmpStrs[3], 0UL, 32UL);
	*((uint32_t *)(&BaseEntry.ReadWriteConfig1)) = ASCIIHexToDword(TmpStrs[4], 0UL, 32UL);
	
	JSONStrapArray = json_object_get(JSONMemClkTblObj, "Strap Entries");
	
	if(!JSONStrapArray) return(0);
	
	if(json_array_size(JSONStrapArray) != Hdr.StrapEntryCount) return(0);
	
	*NewClkTbl = malloc(TableSize);
	
	memcpy(*NewClkTbl, &Hdr, sizeof(NVMemoryClockTableHdr));
	pos = sizeof(NVMemoryClockTableHdr);
	memcpy((*NewClkTbl) + pos, &BaseEntry, sizeof(NVMemoryClockTableBaseEntry));
	pos += sizeof(NVMemoryClockTableBaseEntry);
	
	CurStrapEntry = (NVMemoryClockTableStrapEntry *)((*NewClkTbl) + pos);
	
	for(int i = 0; i < Hdr.StrapEntryCount; ++i)
	{
		json_t *JSONCurEntry = json_array_get(JSONStrapArray, i);
		
		if(!JSONCurEntry)
		{
			free(*NewClkTbl);
			*NewClkTbl = NULL;
			return(0);
		}
		
		ret = json_unpack_ex(JSONCurEntry, NULL, JSON_STRICT, "{ssssssssssss}", "MemTweakIndex", &TmpStrs[0], "Flags0", &TmpStrs[1], "Flags1", &TmpStrs[2], "Flags4", &TmpStrs[3], "Flags5", &TmpStrs[4], \
			"GDDR5XMicronMSR1Offset", &TmpStrs[5]);
		
		if(ret == -1)
		{
			free(*NewClkTbl);
			*NewClkTbl = NULL;
			return(0);
		}
		
		*((uint8_t *)(&CurStrapEntry->MemTweakIndex)) = ASCIIHexToDword(TmpStrs[0], 0UL, 8UL);
		*((uint8_t *)(&CurStrapEntry->Flags0)) = ASCIIHexToDword(TmpStrs[1], 0UL, 8UL);
		*((uint8_t *)(&CurStrapEntry->Flags1)) = ASCIIHexToDword(TmpStrs[2], 0UL, 8UL);
		*((uint8_t *)(&CurStrapEntry->Flags4)) = ASCIIHexToDword(TmpStrs[3], 0UL, 8UL);
		*((uint8_t *)(&CurStrapEntry->Flags5)) = ASCIIHexToDword(TmpStrs[4], 0UL, 8UL);
		*((uint8_t *)(&CurStrapEntry->GDDR5XMicronMSR14Offset)) = ASCIIHexToDword(TmpStrs[5], 0UL, 8UL);
		
		CurStrapEntry++;
	}
	
	return(TableSize);
}

json_t *DumpMemoryTweakTableAsJSON(const NVMemoryTweakTableHdr *TweakTbl)
{
	json_t *JSONTweakTblObj, *JSONHeaderObj, *JSONBaseEntryObj;
	char tmpstrs[9][11];
	uint8_t RDCRC;
		
	DwordToASCIIHex(tmpstrs[0], &TweakTbl->Version, 1U);
	DwordToASCIIHex(tmpstrs[1], &TweakTbl->HeaderSize, 1U);
	DwordToASCIIHex(tmpstrs[2], &TweakTbl->BaseEntrySize, 1U);
	DwordToASCIIHex(tmpstrs[3], &TweakTbl->ExtendedEntrySize, 1U);
	DwordToASCIIHex(tmpstrs[4], &TweakTbl->ExtendedEntryCount, 1U);
	DwordToASCIIHex(tmpstrs[5], &TweakTbl->EntryCount, 1U);
	
	JSONHeaderObj = json_pack("{ssssssssssss}", "Version", tmpstrs[0], "HeaderSize", tmpstrs[1], "BaseEntrySize", tmpstrs[2], "ExtendedEntrySize", tmpstrs[3], \
		"ExtendedEntryCount", tmpstrs[4], "EntryCount", tmpstrs[5]);
		
	NVMemoryTweakTableBaseEntry *MemTweakTblBaseEntry = (NVMemoryTweakTableBaseEntry *)(((uint8_t *)TweakTbl) + sizeof(NVMemoryTweakTableHdr));
	
	// Because RDCRC is such a tiny field (less than a byte!) we need
	// to handle it special. It's a 4-bit field.
	
	RDCRC = amd_bfe(MemTweakTblBaseEntry->RDCRC, 0UL, 4UL);
	
	DwordToASCIIHex(tmpstrs[0], &MemTweakTblBaseEntry->CONFIG0, 4U);
	DwordToASCIIHex(tmpstrs[1], &MemTweakTblBaseEntry->CONFIG1, 4U);
	DwordToASCIIHex(tmpstrs[2], &MemTweakTblBaseEntry->CONFIG2, 4U);
	DwordToASCIIHex(tmpstrs[3], &MemTweakTblBaseEntry->CONFIG3, 4U);
	DwordToASCIIHex(tmpstrs[4], &MemTweakTblBaseEntry->CONFIG4, 4U);
	DwordToASCIIHex(tmpstrs[5], &MemTweakTblBaseEntry->CONFIG5, 4U);
	DwordToASCIIHex(tmpstrs[6], &MemTweakTblBaseEntry->MISCSHIT, 4U);
	DwordToASCIIHex(tmpstrs[7], &RDCRC, 1U);
	DwordToASCIIHex(tmpstrs[8], &MemTweakTblBaseEntry->TIMING22, 4U);
	
	JSONBaseEntryObj = json_pack("{ssssssssssssssssss}", "CONFIG0", tmpstrs[0], "CONFIG1", tmpstrs[1], "CONFIG2", tmpstrs[2], "CONFIG3", tmpstrs[3], \
		"CONFIG4", tmpstrs[4], "CONFIG5", tmpstrs[5], "MISCSHIT", tmpstrs[6], "RDCRC", tmpstrs[7], "TIMING22", tmpstrs[8]);
	
	JSONTweakTblObj = json_pack("{soso}", "Header", JSONHeaderObj, "Base Entry", JSONBaseEntryObj);
		
	//printf("DBG:\n%s\n", json_dumps(JSONTweakTblObj, JSON_INDENT(4)));
	return(JSONTweakTblObj);
}

uint32_t BuildMemoryTweakTable(json_t *JSONMemTweakTblObj, void **NewTweakTbl)
{
	json_t *JSONHeaderObj, *JSONBaseEntryObj;
	NVMemoryTweakTableBaseEntry BaseEntry;
	NVMemoryTweakTableHdr Hdr;
	char TmpStrs[9][11];
	uint8_t RDCRC;
	int ret;
	
	// If we return without having allocated memory for the new table (and, of course, populating it)
	// then it was certainly due to an error condition - so may as well set it as such just once here.
	*NewTweakTbl = NULL;
	
	JSONHeaderObj = json_object_get(JSONMemTweakTblObj, "Header");
	
	if(!JSONHeaderObj) return(0);
	
	ret = json_unpack_ex(JSONHeaderObj, NULL, JSON_STRICT, "{ssssssssssss}", "Version", &TmpStrs[0], "HeaderSize", &TmpStrs[1], "BaseEntrySize", &TmpStrs[2], "ExtendedEntrySize", &TmpStrs[3], \
		"ExtendedEntryCount", &TmpStrs[4], "EntryCount", &TmpStrs[5]);
	
	if(ret == -1) return(0);
	
	Hdr.Version = ASCIIHexToDword(TmpStrs[0], 0UL, 8UL);
	Hdr.HeaderSize = ASCIIHexToDword(TmpStrs[1], 0UL, 8UL);
	Hdr.BaseEntrySize = ASCIIHexToDword(TmpStrs[2], 0UL, 8UL);
	Hdr.ExtendedEntrySize = ASCIIHexToDword(TmpStrs[3], 0UL, 8UL);
	Hdr.ExtendedEntryCount = ASCIIHexToDword(TmpStrs[4], 0UL, 8UL);
	Hdr.EntryCount = ASCIIHexToDword(TmpStrs[5], 0UL, 8UL);
	
	JSONBaseEntryObj = json_object_get(JSONMemTweakTblObj, "Base Entry");
	
	if(!JSONBaseEntryObj) return(0);
	
	ret = json_unpack_ex(JSONBaseEntryObj, NULL, JSON_STRICT, "{ssssssssssssssssss}", "CONFIG0", &TmpStrs[0], "CONFIG1", &TmpStrs[1], "CONFIG2", &TmpStrs[2], "CONFIG3", &TmpStrs[3], \
		"CONFIG4", &TmpStrs[4], "CONFIG5", &TmpStrs[5], "MISCSHIT", &TmpStrs[6], "RDCRC", &TmpStrs[7], "TIMING22", &TmpStrs[8]);
	
	*((uint32_t *)(&BaseEntry.CONFIG0)) = ASCIIHexToDword(TmpStrs[0], 0UL, 32UL);
	*((uint32_t *)(&BaseEntry.CONFIG1)) = ASCIIHexToDword(TmpStrs[1], 0UL, 32UL);
	*((uint32_t *)(&BaseEntry.CONFIG2)) = ASCIIHexToDword(TmpStrs[2], 0UL, 32UL);
	*((uint32_t *)(&BaseEntry.CONFIG3)) = ASCIIHexToDword(TmpStrs[3], 0UL, 32UL);
	*((uint32_t *)(&BaseEntry.CONFIG4)) = ASCIIHexToDword(TmpStrs[4], 0UL, 32UL);
	*((uint32_t *)(&BaseEntry.CONFIG5)) = ASCIIHexToDword(TmpStrs[5], 0UL, 4UL);
	*((uint32_t *)(&BaseEntry.MISCSHIT)) = ASCIIHexToDword(TmpStrs[6], 0UL, 32UL);
	BaseEntry.RDCRC = (uint8_t)ASCIIHexToDword(TmpStrs[7], 0UL, 4UL);
	*((uint32_t *)(&BaseEntry.TIMING22)) = ASCIIHexToDword(TmpStrs[8], 0UL, 32UL);
		
	
	*NewTweakTbl = calloc(1, sizeof(NVMemoryTweakTableHdr) + sizeof(NVMemoryTweakTableBaseEntry));
	memcpy(*NewTweakTbl, &Hdr, sizeof(NVMemoryTweakTableHdr));
	memcpy(((uint8_t *)(*NewTweakTbl)) + sizeof(NVMemoryTweakTableHdr), &BaseEntry, sizeof(NVMemoryTweakTableBaseEntry));
	
	return(sizeof(NVMemoryTweakTableHdr) + sizeof(NVMemoryTweakTableBaseEntry));
}

void ApplyMemoryTweakTable(uint8_t *VBIOSTable, void *NewTweakTable)
{
	NVMemoryTweakTableBaseEntry *VBIOSBaseEntry, *NewBaseEntry;
	
	memcpy(VBIOSTable, NewTweakTable, sizeof(NVMemoryTweakTableHdr));
	
	VBIOSBaseEntry = (NVMemoryTweakTableBaseEntry *)(VBIOSTable + sizeof(NVMemoryTweakTableHdr));
	NewBaseEntry = (NVMemoryTweakTableBaseEntry *)(NewTweakTable + sizeof(NVMemoryTweakTableHdr));
	
	VBIOSBaseEntry->CONFIG0 = NewBaseEntry->CONFIG0;
	VBIOSBaseEntry->CONFIG1 = NewBaseEntry->CONFIG1;
	VBIOSBaseEntry->CONFIG2 = NewBaseEntry->CONFIG2;
	VBIOSBaseEntry->CONFIG3 = NewBaseEntry->CONFIG3;
	VBIOSBaseEntry->CONFIG4 = NewBaseEntry->CONFIG4;
	VBIOSBaseEntry->CONFIG5 = NewBaseEntry->CONFIG5;
	VBIOSBaseEntry->MISCSHIT = NewBaseEntry->MISCSHIT;
	VBIOSBaseEntry->TIMING22 = NewBaseEntry->TIMING22;
	VBIOSBaseEntry->RDCRC = NewBaseEntry->RDCRC;	
}

void die(int RetVal, char *FormattedMsg, ...)
{
	va_list MsgArgs;
	
	va_start(MsgArgs, FormattedMsg);
	vfprintf(stderr, FormattedMsg, MsgArgs);
	va_end(MsgArgs);
	
	exit(RetVal);
}

#define LOG_WARN			0
#define LOG_INFO			1
#define LOG_DEBUG			2
#define LOG_VDBG			3

// Just for now - fuck it.
static const int CurLogLevel = 3;

void DbgPrintf(int severity, const char *msg, ...)
{
	va_list MsgArgs;
	
	if(severity <= CurLogLevel)
	{
		va_start(MsgArgs, msg);
		
		vfprintf(stderr, msg, MsgArgs);
	}
}

int main(int argc, char **argv)
{
	bool WritingVBIOS;
	struct stat stbuf;
	uint8_t *VBIOSImage;
	uint32_t UEFIImageLen;
	FILE *VBIOSFile, *Config;
	json_t *JSONConfigObj, *JSONMemClkTbl, *JSONMemTweakTbl;
	int32_t VBIOSSize, PCIOptionROMHdrOffset, UEFIExpROMBaseOffset, BITOffset, MemClkTblOff, MemTweakTblOff, tmp;
	
	if(argc != 2 && argc != 4) die(1, "Usage: %s [ -c nvconf.json ] <VBIOS Image>\n", argv[0]);
	
	if(argc == 2)
	{
		VBIOSFile = fopen(argv[1], "rb");
		WritingVBIOS = false;
		Config = NULL;
		
		if(!VBIOSFile) die(2, "Failed to open VBIOS image specified (%s) for reading (does it exist?)\n", argv[1]);
		
		stat(argv[1], &stbuf);
		VBIOSSize = stbuf.st_size;
	}
	else if(!strcmp(argv[1], "-c"))
	{
		Config = fopen(argv[2], "rb");
		
		if(!Config) die(2, "Failed to open configuration file specified (%s) for reading (does it exist?)\n", argv[2]);
		
		VBIOSFile = fopen(argv[3], "rb+");
		
		if(!VBIOSFile)
		{
			fclose(Config);
			die(2, "Failed to open VBIOS image specified (%s) for reading and writing (does it exist?)\n", argv[3]);
		}
		
		stat(argv[3], &stbuf);
		VBIOSSize = stbuf.st_size;
		
		WritingVBIOS = true;
	}
	else
	{
		die(1, "Usage: %s [ -c nvconf.json ] <VBIOS Image>\n", argv[0]);
	}
	
	
	// Sloppy and not proper way to get the size,
	// however it will function on Windows & *nix
	//fseek(VBIOSFile, 0UL, SEEK_END);
	//VBIOSSize = ftell(VBIOSFile);
	//rewind(VBIOSFile);
	//printf("File size: 0x%08X\n", VBIOSSize);
	
	
	VBIOSImage = (uint8_t *)malloc(sizeof(uint8_t) * VBIOSSize);
	if(fread(VBIOSImage, sizeof(uint8_t), VBIOSSize, VBIOSFile) != VBIOSSize)
	{
		free(VBIOSImage);
		fclose(VBIOSFile);
		if(Config) fclose(Config);
		die(3, "Failed to read entire VBIOS file.\n");
	}
	
	rewind(VBIOSFile);
	
	PCIOptionROMHdrOffset = GetPCIOptionROMOffset(VBIOSImage, VBIOSSize);
	
	if(PCIOptionROMHdrOffset == -1)
	{
		free(VBIOSImage);
		fclose(VBIOSFile);
		if(Config) fclose(Config);
		die(4, "PCI Expansion ROM not found.\n");
	}
	
	UEFIExpROMBaseOffset = GetUEFIOptionROMImage(VBIOSImage, PCIOptionROMHdrOffset);
	
	//printf("UEFI Option ROM base offset is 0x%08X.\n", UEFIExpROMBaseOffset);
	
	PCIRDataStructure *PCIR = (PCIRDataStructure *)(VBIOSImage + UEFIExpROMBaseOffset + *((uint16_t *)(VBIOSImage + UEFIExpROMBaseOffset + 0x18)));
	
	UEFIImageLen = PCIR->ImageLength << 9;
	
	BITOffset = FindBITOffset(VBIOSImage, PCIOptionROMHdrOffset, VBIOSSize);
	
	if(BITOffset == -1)
	{
		free(VBIOSImage);
		fclose(VBIOSFile);
		if(Config) fclose(Config);
		die(4, "Unable to find BIT header (is this a valid Nvidia VBIOS?)\n");
	}
	
	BITHeader *Hdr = (BITHeader *)(VBIOSImage + BITOffset);
	
	/*
	BITToken *CurToken = (BITToken *)(((uint8_t *)Hdr) + sizeof(BITHeader));
	
	for(int i = 0; i < Hdr->TokenEntryCount; ++i)
	{
		switch(CurToken[i].ID)
		{
			case '2':
				DumpBITI2CPtrs(VBIOSImage, CurToken + i);
				break;
			case 'B':
				DumpBITBIOSDatav2(VBIOSImage, CurToken + i);
				break;
			case 'C':
				DumpBITClockPtrs(VBIOSImage, CurToken + i);
				break;
			case 'D':
				DumpBITDFPPtrs(VBIOSImage, CurToken + i);
				break;
			case 'I':
				DumpBITNVInitPtrs(VBIOSImage, CurToken + i);
				break;
			case 'M':
				DumpBITMemoryPtrsv2(VBIOSImage, CurToken + i);
				break;
			case 'N':
				continue;
			case 'P':
				DumpBITPerfPtrsv2(VBIOSImage, CurToken + i);
				break;
			case 'S':
				DumpBITStringPtrsv2(VBIOSImage, CurToken + i);
				break;
			case 'T':
				DumpBITTMDSPtrs(VBIOSImage, CurToken + i);
				break;
			case 'U':
				DumpBITDisplayPtrs(VBIOSImage, CurToken + i);
				break;
			case 'V':
				DumpBITVirtualPtrs(VBIOSImage, CurToken + i);
				break;
			case 'x':
				DumpBITMXMData(VBIOSImage, CurToken + i);
				break;
			case 'd':
				DumpBITDPPtrs(VBIOSImage, CurToken + i);
				break;
			case 'p':
				DumpBITFalconData(VBIOSImage, CurToken + i);
				break;
			case 'u':
				DumpBITUEFIData(VBIOSImage, CurToken + i);
				break;
			default:
				DumpBITToken(VBIOSImage, CurToken + i);
		}
	}
	
	// TODO/FIXME: Validate BIT header checksum.
	
	*/
	
	tmp = FindBITToken(Hdr, 'P', 2);
	
	if(tmp == -1)
	{
		free(VBIOSImage);
		fclose(VBIOSFile);
		if(Config) fclose(Config);
		die(4, "Unable to find BIT token BIT_PERF_PTRS with version 2 (is this a valid Nvidia VBIOS?)\n");
	}
	
	BITToken *PerfPtrsToken = (BITToken *)(VBIOSImage + BITOffset + sizeof(BITHeader) + (sizeof(BITToken) * tmp));
	
	BITPerfPtrsv2 *PerfPtrs = (BITPerfPtrsv2 *)(VBIOSImage + PCIOptionROMHdrOffset + PerfPtrsToken->DataOffset);
	
	MemClkTblOff = PCIOptionROMHdrOffset + UEFIImageLen + PerfPtrs->MemoryClockTblPtr;
	MemTweakTblOff = PCIOptionROMHdrOffset + UEFIImageLen + PerfPtrs->MemoryTweakTblPtr;
	
	DbgPrintf(LOG_VDBG, "Memory Clock Table offset is: 0x%08X.\nMemory Tweak Table Offset is at 0x%08X.\n", MemClkTblOff, MemTweakTblOff);
	
	//printf("Memory Clock Table Offset: 0x%08X\n", MemClkTblOff);
	//printf("Is it 0x11?! 0x%02X!\n", VBIOSImage[MemClkTblOff]);
	
	//DumpMemoryClockTable(((NVMemoryClockTableHdr *)(VBIOSImage + MemClkTblOff)));
	//DumpMemoryTweakTable(((NVMemoryTweakTableHdr *)(VBIOSImage + MemTweakTblOff)));
	
	if(!WritingVBIOS)
	{
		JSONMemClkTbl = DumpMemoryClockTableAsJSON(((NVMemoryClockTableHdr *)(VBIOSImage + MemClkTblOff)));
		JSONMemTweakTbl = DumpMemoryTweakTableAsJSON(((NVMemoryTweakTableHdr *)(VBIOSImage + MemTweakTblOff)));
		JSONConfigObj = json_pack("{soso}", "Memory Clock Table", JSONMemClkTbl, "Memory Tweak Table", JSONMemTweakTbl);
		
		// This is going to stdout on purpose - and it should be the ONLY thing that does when emitting the config data!
		fprintf(stdout, "\n%s\n", json_dumps(JSONConfigObj, JSON_INDENT(4)));
	}
	else
	{
		int ret;
		NVMemoryClockTableHdr *NewMemClkTbl;
		NVMemoryTweakTableHdr *NewMemTweakTbl;
		
		JSONConfigObj = json_loadf(Config, JSON_DISABLE_EOF_CHECK, NULL);
		fclose(Config);
		
		if(!JSONConfigObj)
		{
			free(VBIOSImage);
			die(5, "Failed to parse configuration file supplied as JSON.\n");
		}
		
		JSONMemClkTbl = json_object_get(JSONConfigObj, "Memory Clock Table");
		
		if(!JSONMemClkTbl || !ret)
		{
			json_decref(JSONConfigObj);
			free(VBIOSImage);
			die(6, "Failed to parse configuration file data.\n");
		}
		
		ret = BuildMemoryClockTable(JSONMemClkTbl, &NewMemClkTbl);
		
		if(!NewMemClkTbl || !ret)
		{
			json_decref(JSONConfigObj);
			free(VBIOSImage);
			die(6, "Failed to parse configuration file data.\n");
		}
		
		memcpy(VBIOSImage + MemClkTblOff, NewMemClkTbl, sizeof(NVMemoryClockTableHdr) + NewMemClkTbl->BaseEntrySize + (NewMemClkTbl->StrapEntrySize * NewMemClkTbl->StrapEntryCount));
		
		JSONMemTweakTbl = json_object_get(JSONConfigObj, "Memory Tweak Table");
		
		if(!JSONMemTweakTbl)
		{
			json_decref(JSONConfigObj);
			free(VBIOSImage);
			die(6, "Failed to parse configuration file data.\n");
		}
		
		ret = BuildMemoryTweakTable(JSONMemTweakTbl, &NewMemTweakTbl);
		
		if(!NewMemTweakTbl || !ret)
		{
			json_decref(JSONConfigObj);
			free(VBIOSImage);
			die(6, "Failed to parse configuration file data.\n");
		}
		
		memcpy(VBIOSImage + MemTweakTblOff, NewMemTweakTbl, sizeof(NVMemoryTweakTableHdr) + sizeof(NVMemoryTweakTableBaseEntry));
		
		printf("Memory compare on Memory Tweak Table: %s\n", ((!memcmp(VBIOSImage + MemClkTblOff, NewMemClkTbl, sizeof(NVMemoryTweakTableHdr) + sizeof(NVMemoryTweakTableBaseEntry))) ? "Failed" : "Passed"));
		
		fwrite(VBIOSImage, sizeof(uint8_t), VBIOSSize, VBIOSFile);
		json_decref(JSONConfigObj);
		
		free(NewMemTweakTbl);
		free(NewMemClkTbl);
	}
	
	
	free(VBIOSImage);
	fclose(VBIOSFile);
	return(0);
}
