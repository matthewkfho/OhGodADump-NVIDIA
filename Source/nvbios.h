// Copyright ∞ Kristy-Leigh "OhGodAGirl" Minehan and NVIDIA Corporation.
//             www.ohgodagirl.com | www.github.com/OhGodAGirl
// Questions? Come spam me, baby, at ohgodagirl@gmail.com

#ifndef __NVBIOS_H
#define __NVBIOS_H

#define NV_BIT_HEADER_IDENTIFIER		0xB8FF
#define NV_BIT_HEADER_SIGNATURE			0x00544942

#define	NV_BIT_TOKEN_PERF_PTRS			0x50

#define PCIR_HEADER_SIGNATURE			0x52494350

#define SEGOFFTOLINEAR(x)				((((x) & 0xFFFFU) << 4) + (((x) & 0xFFFF0000U) >> 16))

#pragma pack(push, 1)

typedef struct _BITHeader
{
	uint16_t ID;
	uint32_t Sig;
	uint16_t BCDVersion;
	uint8_t HeaderSize;
	uint8_t TokenSize;
	uint8_t TokenEntryCount;
	uint8_t Checksum;
} BITHeader;

typedef struct _BITToken
{
	uint8_t ID;
	uint8_t DataVersion;
	uint16_t DataSize;
	uint16_t DataOffset;
} BITToken;

typedef struct _BITI2CPtrs
{
	uint16_t I2CScriptsPtr;
	uint16_t ExtHWMonInitPtr;
} BITI2CPtrs;

typedef struct _BITBIOSDatav2
{
	uint32_t BIOSVersion;
	uint8_t BIOSOEMVersion;
	uint8_t BIOSChecksum;
	uint16_t Int15POSTCallbacks;
	uint16_t Int15SystemCallbacks;
	uint16_t FrameCount;
	uint32_t Reserved;
	uint8_t MaxHeadsAtPOST;
	uint8_t MemorySizeReport;
	uint8_t HorizontalScaleFactor;
	uint8_t VerticalScaleFactor;
	uint16_t DataRangeTablePtr;
	uint16_t ROMpacksPtr;
	uint16_t AppliedROMpacksPtr;
	uint8_t AppliedROMpacksMax;
	uint8_t AppliedROMpacksCount;
	uint8_t ModuleMapExternal0;
	uint32_t CompressionInfoPtr;
} BITBIOSDatav2;

typedef struct _BITClockPtrsv2
{
	uint32_t VBEModePCLKTblPtr;
	uint32_t ClocksTblPtr;
	uint32_t ClockProgrammingTblPtr;
	uint32_t NAFLLTblPtr;
	uint32_t ADCTblPtr;
	uint32_t FreqControllerTblPtr;
} BITClockPtrsv2;

typedef struct _BITDFPPtrs
{
	uint16_t VESAEstablishedTimingTblsPtr;
	uint16_t VBIOSInternalFlatPanelTblsPtr;
} BITDFPPtrs;

typedef struct _BITNVInitPtrs
{
	uint16_t InitScriptTblPtr;
	uint16_t MacroIndexTblPtr;
	uint16_t MacroTblPtr;
	uint16_t ConditionTblPtr;
	uint16_t IOConditionTblPtr;
	uint16_t IOFlagConditionTblPtr;
	uint16_t InitFunctionTblPtr;
	uint16_t VBIOSPrivateBootScriptPtr;
	uint16_t DataArraysTblPtr;
	uint16_t PCIeSettingsScriptPtr;
	uint16_t DevinitTblsPtr;
	uint16_t DevinitTblsSize;
	uint16_t BootScriptsPtr;
	uint16_t BootScriptsSize;
	uint16_t NVLinkConfigDataPtr;
	uint16_t BootScriptsNonGC6Ptr;
	uint16_t BootScriptsNonGC6Size;
} BITNVInitPtrs;

typedef struct _BITMemoryPtrsv2
{
	uint8_t MemoryStrapDataCount;
	uint16_t MemoryStrapTranslationTablePtr;
	uint16_t MemoryInformationTablePtr;
	uint32_t MemoryTrainingTablePtr;
	uint32_t MemoryTrainingPatternTablePtr;
	uint32_t MemoryPartitionInformationTbl;
	uint32_t MemoryScriptListPtr;
} BITMemoryPtrsv2;

typedef struct _BITPerfPtrsv2
{
	uint32_t PerformanceTblPtr;
	uint32_t MemoryClockTblPtr;
	uint32_t MemoryTweakTblPtr;
	uint32_t PowerControlTblPtr;
	uint32_t ThermalControlTblPtr;
	uint32_t ThermalDeviceTblPtr;
	uint32_t ThermalCoolersTblPtr;
	uint32_t PerformanceSettingsScriptPtr;
	uint32_t ContinuousVirtualBinningTblPtr;
	uint32_t VenturaTblPtr;
	uint32_t PowerSensorsTblPtr;
	uint32_t PowerCappingTblPtr;
	uint32_t PStateClockRangeTblPtr;
	uint32_t VoltageFrequencyTblPtr;
	uint32_t VirtualPStateTblPtr;
	uint32_t PowerTopologyTblPtr;
	uint32_t PowerLeakageTblPtr;
	uint32_t PerformanceTestSpecificationsTblPtr;
	uint32_t ThermalChannelTblPtr;
	uint32_t ThermalAdjustmentTblPtr;
	uint32_t ThermalPolicyTblPtr;
	uint32_t PStateMemoryClockFrequencyTblPtr;
	uint32_t FanCoolerTblPtr;
	uint32_t FanPolicyTblPtr;
	uint32_t DIDTTblPtr;
	uint32_t FanTestTblPtr;
	uint32_t VoltageRailTblPtr;
	uint32_t VoltageDeviceTblPtr;
	uint32_t VoltagePolicyTblPtr;
	uint32_t LowPowerTblPtr;
	uint32_t LowPowerPCIeTblPtr;
	uint32_t LowPowerPCIePlatformTblPtr;
	uint32_t LowPowerGRTblPtr;
	uint32_t LowPowerMSTblPtr;
	uint32_t LowPowerDITblPtr;
	uint32_t LowPowerGC6TblPtr;
	uint32_t LowPowerPSITblPtr;
	uint32_t ThermalMonitorTblPtr;
	uint32_t OverclockingTblPtr;
	uint32_t LowPowerNVLINKTblPtr;
} BITPerfPtrsv2;

typedef struct _BITStringPtrsv2
{
	uint16_t SignOnMsgPtr;
	uint8_t SignOnMsgMaxLen;
	uint16_t VersionMsgPtr;
	uint8_t VersionMsgMaxLen;
	uint16_t CopyrightMsgPtr;
	uint8_t CopyrightMsgMaxLen;
	uint16_t OEMMsgPtr;
	uint8_t OEMMsgMaxLen;
	uint16_t OEMVendorNameMsgPtr;
	uint8_t OEMVendorNameMsgMaxLen;
	uint16_t OEMProductNameMsgPtr;
	uint8_t OEMProductNameMsgMaxLen;
	uint16_t OEMProductRevisionMsgPtr;
	uint8_t OEMProductRevisionMsgMaxLen;
} BITStringPtrsv2;

typedef struct _BITTMDSPtrs
{
	uint16_t TMDSInfoTblPtr;
} BITTMDSPtrs;

typedef struct _BITDisplayPtrs
{
	uint16_t DisplayScriptingTblPtr;
	uint8_t DisplayControlFlags;
	uint16_t SLITblHdrPtr;
} BITDisplayPtrs;

typedef struct _BITVirtualPtrs
{
	uint16_t VirtualStrapFieldTblPtr;
	uint16_t VirtualStrapFieldRegister;
	uint16_t TranslationTblPtr;
} BITVirtualPtrs;

typedef struct _BITMXMData
{
	uint8_t ModuleSpecVersion;
	uint8_t ModuleFlags0;
	uint8_t ConfigFlags0;
	uint8_t DPDriveStrengthScale;
	uint16_t MXMDigitalConnectorTblPtr;
	uint16_t MXMDDCAuxToCCBTblPtr;
} BITMXMData;

typedef struct _BITDPPtrs
{
	uint16_t DPInfoTblPtr;
} BITDPPtrs;

typedef struct _BITFalconDatav2
{
	uint32_t FalconUcodeTblPtr;
} BITFalconDatav2;

typedef struct _BITUEFIData
{
	uint32_t MinimumUEFIDriverVersion;
	uint8_t UEFICompatibilityLevel;
	uint64_t UEFIFlags;
} BITUEFIData;

typedef struct _PCIRDataStructure
{
	uint32_t Sig;
	uint16_t VendorID;
	uint16_t DeviceID;
	uint16_t Reserved0;
	uint16_t Length;
	uint8_t Revision;
	uint8_t ClassCode[3];
	uint16_t ImageLength;
	uint16_t CodeRevision;
	uint8_t CodeType;
	uint8_t Indicator;
	uint16_t Reserved1;
} PCIRDataStructure;

typedef struct _NVMemoryClockTableHdr
{
	uint8_t Version;
	uint8_t HeaderSize;
	uint8_t BaseEntrySize;
	uint8_t StrapEntrySize;			// This is NOT sizeof(NVMemoryClockTableStrapEntry)! It's the amount of space in it used for data!
	uint8_t StrapEntryCount;
	uint8_t EntryCount;
} NVMemoryClockTableHdr;

typedef struct _NVMemoryClockTableBaseEntry
{
	union
	{
		uint16_t MinFrequency : 14;
		uint16_t Reserved0 : 2;
	} MinFreq;
	
	union
	{
		uint16_t MaxFrequency : 14;
		uint16_t Reserved1 : 2;
	} MaxFreq;
	
	uint32_t Reserved0;
	
	union
	{
		uint8_t Reserved0 : 1;
		uint8_t GearShift : 1;
		uint8_t ExtendedQUSE : 2;
		uint8_t Reserved1 : 2;
		uint8_t SDM : 1;
		uint8_t Reserved2 : 1;
	} Flags0;
	
	union
	{
		uint32_t ReadSettings0 : 9;
		uint32_t WriteSettings0 : 9;
		uint32_t Reserved0 : 2;
		uint32_t ReadSettings1 : 5;
		uint32_t Reserved1 : 7;
	} ReadWriteConfig0;
	
	union
	{
		uint32_t ReadSettings0 : 4;
		uint32_t WriteSettings0 : 4;
		uint32_t ReadSettings1 : 4;
		uint32_t WriteSettings1 : 4;
		uint32_t ReadSettings2 : 4;
		uint32_t WriteSettings2 : 4;
		uint32_t TimingSettings0 : 8;
	} ReadWriteConfig1;
	
	uint8_t Reserved1;
	uint16_t Reserved2;
} NVMemoryClockTableBaseEntry;

typedef struct _NVMemoryClockTableStrapEntry
{
	uint8_t MemTweakIndex;
	
	union
	{
		uint8_t Reserved : 7;
		uint8_t AlignmentMode : 1;
	} Flags0;
	
	union
	{
		uint8_t Config5VDDPMode : 2;
		uint8_t FBVDDQVoltage : 1;
		uint8_t GDDR5FBVREF : 1;
		uint8_t MemoryVREFD : 1;
		uint8_t Reserved : 3;
	} Flags1;
	
	uint8_t Reserved0[5];
	
	union
	{
		uint8_t Reserved : 7;
		uint8_t MRS7GDDR5 : 1;
	} Flags4;
	
	uint8_t Reserved1;
	
	union
	{
		uint8_t Reserved0 : 3;
		uint8_t GDDR5XMR8 : 1;
		uint8_t Reserved1 : 2;
		uint8_t GDDR5XInternalVREFC : 1;
		uint8_t Reserved2 : 1;
	} Flags5;
	
	union
	{
		uint8_t MRS14MicronCoreVoltage : 6;
		uint8_t MRS14GDDR5XSubregisterSelect : 1;
		uint8_t Reserved : 1;
	} GDDR5XMicronMSR14Offset;
	
	uint8_t Reserved2[14];
} NVMemoryClockTableStrapEntry;

typedef struct _NVMemoryTweakTableHdr
{
	uint8_t Version;
	uint8_t HeaderSize;
	uint8_t BaseEntrySize;
	uint8_t ExtendedEntrySize;
	uint8_t ExtendedEntryCount;
	uint8_t EntryCount;
} NVMemoryTweakTableHdr;

typedef struct _NVMemoryTweakTableBaseEntry
{
	union
	{
		uint32_t RC : 8;
		uint32_t RFC : 9;
		uint32_t RAS : 7;
		uint32_t RP : 7;
		uint32_t Reserved : 1;
	} CONFIG0;
	
	union
	{
		uint32_t CL : 7;
		uint32_t WL : 7;
		uint32_t RD_RCD : 6;
		uint32_t WR_RCD : 6;
		uint32_t Reserved : 6;
	} CONFIG1;
	
	union
	{
		uint32_t RPRE : 4;
		uint32_t WPRE : 4;
		uint32_t CDLR : 7;
		uint32_t AmbiguousField0 : 1;
		uint32_t WR : 7;
		uint32_t AmbiguousField1 : 1;
		uint32_t W2R_BUS : 4;
		uint32_t R2W_BUS : 4;
	} CONFIG2;
	
	union
	{
		uint32_t PDEX : 5;
		uint32_t PDEN2PDEX : 4;
		uint32_t FAW : 7;
		uint32_t AOND : 8;
		uint32_t CCDL : 4;
		uint32_t CCDS : 4;
	} CONFIG3;
	
	union
	{
		uint32_t REFRESH_LO : 3;
		uint32_t REFRESH : 12;
		uint32_t RRD : 6;
		uint32_t DELAY0 : 6;
		uint32_t Reserved : 5;
	} CONFIG4;
	
	union
	{
		uint32_t ADR_MIN : 3;
		uint32_t Reserved0 : 1;
		uint32_t WRCRC : 7;
		uint32_t Reserved1 : 1;
		uint32_t OFFSET0 : 6;
		uint32_t INTRP_MSB : 2;
		uint32_t OFFSET1 : 4;
		uint32_t OFFSET2 : 4;
		uint32_t INTRP : 4;
	} CONFIG5;
	
	uint8_t Reserved0[23];
	
	// This is not grouped in the spec.
	union
	{
		uint32_t DriveStrength : 2;
		uint32_t Voltage0 : 3;
		uint32_t Voltage1 : 3;
		uint32_t Voltage2 : 3;
		uint32_t R2P : 5;
		uint32_t Voltage3 : 3;
		uint32_t Reserved1 : 1;
		uint32_t Voltage4 : 3;
		uint32_t Reserved2 : 1;
		uint32_t Voltage5 : 3;
		uint32_t Reserved3 : 5;
	} MISCSHIT;
	
	uint32_t RDCRC : 4;
	uint32_t Reserved4 : 28;
	
	uint8_t Reserved5;
	
	union
	{
		uint32_t RFCSBA : 10;
		uint32_t RFCSBR : 8;
		uint32_t Reserved : 14;
	} TIMING22;
	
	uint64_t Reserved6[2];
	
} NVMemoryTweakTableBaseEntry;

#pragma pack(pop)

#endif
