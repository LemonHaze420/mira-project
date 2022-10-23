// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com

/*
	Implemented from: https://github.com/xvortex/ps4-hen-vtx
	Ported by: kiwidog (@kd_tech_)

	Bugfixes: SiSTRo (https://github.com/SiSTR0), SocraticBliss (https://github.com/SocraticBliss)
*/

#include "FakePkgManager.hpp"
#include <Utils/Kernel.hpp>
#include <Utils/Kdlsym.hpp>
#include <Utils/_Syscall.hpp>
#include <Utils/Logger.hpp>
#include <Utils/SysWrappers.hpp>
#include <Boot/Config.hpp>

#include <OrbisOS/Utilities.hpp>

#include <Mira.hpp>
#include <Boot/Config.hpp>

extern "C"
{
	#include <sys/eventhandler.h>
        #include <sys/filedesc.h>
	#include <sys/sysent.h>
	#include <sys/proc.h>
	#include <sys/mman.h>
	#include <sys/ptrace.h>
	#include <sys/wait.h>
	#include <sys/signal.h>
};

using namespace Mira::Plugins;
using namespace Mira::OrbisOS;

#pragma region "Fake-Self-Keys"
const uint8_t FakePkgManager::g_ypkg_p[] =
{
	0x2D, 0xE8, 0xB4, 0x65, 0xBE, 0x05, 0x78, 0x6A, 0x89, 0x31, 0xC9, 0x5A, 0x44, 0xDE, 0x50, 0xC1,
	0xC7, 0xFD, 0x9D, 0x3E, 0x21, 0x42, 0x17, 0x40, 0x79, 0xF9, 0xC9, 0x41, 0xC1, 0xFC, 0xD7, 0x0F,
	0x34, 0x76, 0xA3, 0xE2, 0xC0, 0x1B, 0x5A, 0x20, 0x0F, 0xAF, 0x2F, 0x52, 0xCD, 0x83, 0x34, 0x72,
	0xAF, 0xB3, 0x12, 0x33, 0x21, 0x2C, 0x20, 0xB0, 0xC6, 0xA0, 0x2D, 0xB1, 0x59, 0xE3, 0xA7, 0xB0,
	0x4E, 0x1C, 0x4C, 0x5B, 0x5F, 0x10, 0x9A, 0x50, 0x18, 0xCC, 0x86, 0x79, 0x25, 0xFF, 0x10, 0x02,
	0x8F, 0x90, 0x03, 0xA9, 0x37, 0xBA, 0xF2, 0x1C, 0x13, 0xCC, 0x09, 0x45, 0x15, 0xB8, 0x55, 0x74,
	0x0A, 0x28, 0x24, 0x04, 0xD1, 0x19, 0xAB, 0xB3, 0xCA, 0x44, 0xB6, 0xF8, 0x3D, 0xB1, 0x2A, 0x72,
	0x88, 0x35, 0xE4, 0x86, 0x6B, 0x55, 0x47, 0x08, 0x25, 0x16, 0xAB, 0x69, 0x1D, 0xBF, 0xF6, 0xFE,
};

const uint8_t FakePkgManager::g_ypkg_q[] =
{
	0x23, 0x80, 0x77, 0x84, 0x4D, 0x6F, 0x9B, 0x24, 0x51, 0xFE, 0x2A, 0x6B, 0x28, 0x80, 0xA1, 0x9E,
	0xBD, 0x6D, 0x18, 0xCA, 0x8D, 0x7D, 0x9E, 0x79, 0x5A, 0xE0, 0xB8, 0xEB, 0xD1, 0x3D, 0xF3, 0xD9,
	0x02, 0x90, 0x2A, 0xA7, 0xB5, 0x7E, 0x9A, 0xA2, 0xD7, 0x2F, 0x21, 0xA8, 0x50, 0x7D, 0x8C, 0xA1,
	0x91, 0x2F, 0xBF, 0x97, 0xBE, 0x92, 0xC2, 0xC1, 0x0D, 0x8C, 0x0C, 0x1F, 0xDE, 0x31, 0x35, 0x15,
	0x39, 0x90, 0xCC, 0x97, 0x47, 0x2E, 0x7F, 0x09, 0xE9, 0xC3, 0x9C, 0xCE, 0x91, 0xB2, 0xC8, 0x58,
	0x76, 0xE8, 0x70, 0x1D, 0x72, 0x5F, 0x4A, 0xE6, 0xAA, 0x36, 0x22, 0x94, 0xC6, 0x52, 0x90, 0xB3,
	0x9F, 0x9B, 0xF0, 0xEF, 0x57, 0x8E, 0x53, 0xC3, 0xE3, 0x30, 0xC9, 0xD7, 0xB0, 0x3A, 0x0C, 0x79,
	0x1B, 0x97, 0xA8, 0xD4, 0x81, 0x22, 0xD2, 0xB0, 0x82, 0x62, 0x7D, 0x00, 0x58, 0x47, 0x9E, 0xC7,
};

const uint8_t FakePkgManager::g_ypkg_dmp1[] =
{
	0x25, 0x54, 0xDB, 0xFD, 0x86, 0x45, 0x97, 0x9A, 0x1E, 0x17, 0xF0, 0xE3, 0xA5, 0x92, 0x0F, 0x12,
	0x2A, 0x5C, 0x4C, 0xA6, 0xA5, 0xCF, 0x7F, 0xE8, 0x5B, 0xF3, 0x65, 0x1A, 0xC8, 0xCF, 0x9B, 0xB9,
	0x2A, 0xC9, 0x90, 0x5D, 0xD4, 0x08, 0xCF, 0xF6, 0x03, 0x5A, 0x5A, 0xFC, 0x9E, 0xB6, 0xDB, 0x11,
	0xED, 0xE2, 0x3D, 0x62, 0xC1, 0xFC, 0x88, 0x5D, 0x97, 0xAC, 0x31, 0x2D, 0xC3, 0x15, 0xAD, 0x70,
	0x05, 0xBE, 0xA0, 0x5A, 0xE6, 0x34, 0x9C, 0x44, 0x78, 0x2B, 0xE5, 0xFE, 0x38, 0x56, 0xD4, 0x68,
	0x83, 0x13, 0xA4, 0xE6, 0xFA, 0xD2, 0x9C, 0xAB, 0xAC, 0x89, 0x5F, 0x10, 0x8F, 0x75, 0x6F, 0x04,
	0xBC, 0xAE, 0xB9, 0xBC, 0xB7, 0x1D, 0x42, 0xFA, 0x4E, 0x94, 0x1F, 0xB4, 0x0A, 0x27, 0x9C, 0x6B,
	0xAB, 0xC7, 0xD2, 0xEB, 0x27, 0x42, 0x52, 0x29, 0x41, 0xC8, 0x25, 0x40, 0x54, 0xE0, 0x48, 0x6D,
};

const uint8_t FakePkgManager::g_ypkg_dmq1[] =
{
	0x4D, 0x35, 0x67, 0x38, 0xBC, 0x90, 0x3E, 0x3B, 0xAA, 0x6C, 0xBC, 0xF2, 0xEB, 0x9E, 0x45, 0xD2,
	0x09, 0x2F, 0xCA, 0x3A, 0x9C, 0x02, 0x36, 0xAD, 0x2E, 0xC1, 0xB1, 0xB2, 0x6D, 0x7C, 0x1F, 0x6B,
	0xA1, 0x8F, 0x62, 0x20, 0x8C, 0xD6, 0x6C, 0x36, 0xD6, 0x5A, 0x54, 0x9E, 0x30, 0xA9, 0xA8, 0x25,
	0x3D, 0x94, 0x12, 0x3E, 0x0D, 0x16, 0x1B, 0xF0, 0x86, 0x42, 0x72, 0xE0, 0xD6, 0x9C, 0x39, 0x68,
	0xDB, 0x11, 0x80, 0x96, 0x18, 0x2B, 0x71, 0x41, 0x48, 0x78, 0xE8, 0x17, 0x8B, 0x7D, 0x00, 0x1F,
	0x16, 0x68, 0xD2, 0x75, 0x97, 0xB5, 0xE0, 0xF2, 0x6D, 0x0C, 0x75, 0xAC, 0x16, 0xD9, 0xD5, 0xB1,
	0xB5, 0x8B, 0xE8, 0xD0, 0xBF, 0xA7, 0x1F, 0x61, 0x5B, 0x08, 0xF8, 0x68, 0xE7, 0xF0, 0xD1, 0xBC,
	0x39, 0x60, 0xBF, 0x55, 0x9C, 0x7C, 0x20, 0x30, 0xE8, 0x50, 0x28, 0x44, 0x02, 0xCE, 0x51, 0x2A,
};

const uint8_t FakePkgManager::g_ypkg_iqmp[] =
{
	0xF5, 0x73, 0xB8, 0x7E, 0x5C, 0x98, 0x7C, 0x87, 0x67, 0xF1, 0xDA, 0xAE, 0xA0, 0xF9, 0x4B, 0xAB,
	0x77, 0xD8, 0xCE, 0x64, 0x6A, 0xC1, 0x4F, 0xA6, 0x9B, 0xB9, 0xAA, 0xCC, 0x76, 0x09, 0xA4, 0x3F,
	0xB9, 0xFA, 0xF5, 0x62, 0x84, 0x0A, 0xB8, 0x49, 0x02, 0xDF, 0x9E, 0xC4, 0x1A, 0x37, 0xD3, 0x56,
	0x0D, 0xA4, 0x6E, 0x15, 0x07, 0x15, 0xA0, 0x8D, 0x97, 0x9D, 0x92, 0x20, 0x43, 0x52, 0xC3, 0xB2,
	0xFD, 0xF7, 0xD3, 0xF3, 0x69, 0xA2, 0x28, 0x4F, 0x62, 0x6F, 0x80, 0x40, 0x5F, 0x3B, 0x80, 0x1E,
	0x5E, 0x38, 0x0D, 0x8B, 0x56, 0xA8, 0x56, 0x58, 0xD8, 0xD9, 0x6F, 0xEA, 0x12, 0x2A, 0x40, 0x16,
	0xC1, 0xED, 0x3D, 0x27, 0x16, 0xA0, 0x63, 0x97, 0x61, 0x39, 0x55, 0xCC, 0x8A, 0x05, 0xFA, 0x08,
	0x28, 0xFD, 0x55, 0x56, 0x31, 0x94, 0x65, 0x05, 0xE7, 0xD3, 0x57, 0x6C, 0x0D, 0x1C, 0x67, 0x0B,
};

const uint8_t FakePkgManager::g_RifDebugKey[] =
{
	0x96, 0xC2, 0x26, 0x8D, 0x69, 0x26, 0x1C, 0x8B, 0x1E, 0x3B, 0x6B, 0xFF, 0x2F, 0xE0, 0x4E, 0x12
};

const uint8_t FakePkgManager::g_FakeKeySeed[] =
{
	0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45, 0x46, 0x41, 0x4B, 0x45,
};

#pragma endregion

FakePkgManager::FakePkgManager() :
    m_NpdrmDecryptIsolatedRifHook(nullptr),
    m_NpdrmDecryptRifNewHook(nullptr),
    m_SceSblDriverSendMsgHook(nullptr),
    m_SceSblKeymgrInvalidateKey(nullptr),
    m_SceSblPfsSetKeysHook(nullptr),
    m_processStartEvent(nullptr),
    m_resumeEvent(nullptr)
{
	auto sv = (struct sysentvec*)kdlsym(self_orbis_sysvec);
	struct sysent* sysents = sv->sv_table;
	uint8_t* s_TrampolineF = reinterpret_cast<uint8_t*>(sysents[SYS___MAC_GET_LINK].sy_call); // syscall #410
	uint8_t* s_TrampolineG = reinterpret_cast<uint8_t*>(sysents[SYS___MAC_SET_FD].sy_call); // syscall #388
	uint8_t* s_TrampolineH = reinterpret_cast<uint8_t*>(sysents[SYS___MAC_SET_FILE].sy_call); // syscall #389
	uint8_t* s_TrampolineI = reinterpret_cast<uint8_t*>(sysents[SYS___MAC_SET_LINK].sy_call); // syscall #411
	uint8_t* s_TrampolineJ = reinterpret_cast<uint8_t*>(sysents[SYS_MAC_SYSCALL].sy_call); // syscall #394
	uint8_t* s_TrampolineK = reinterpret_cast<uint8_t*>(sysents[SYS___MAC_EXECVE].sy_call); // syscall #415

	Utilities::HookFunctionCall(s_TrampolineF, reinterpret_cast<void*>(OnNpdrmDecryptIsolatedRif), kdlsym(npdrm_decrypt_isolated_rif__sceSblKeymgrSmCallfunc_hook));
	Utilities::HookFunctionCall(s_TrampolineG, reinterpret_cast<void*>(OnNpdrmDecryptRifNew), kdlsym(npdrm_decrypt_rif_new__sceSblKeymgrSmCallfunc_hook));
	Utilities::HookFunctionCall(s_TrampolineH, reinterpret_cast<void*>(OnSceSblPfsSetKeys), kdlsym(mountpfs__sceSblPfsSetKeys_hookA));
	Utilities::HookFunctionCall(s_TrampolineI, reinterpret_cast<void*>(OnSceSblPfsSetKeys), kdlsym(mountpfs__sceSblPfsSetKeys_hookB));
	Utilities::HookFunctionCall(s_TrampolineJ, reinterpret_cast<void*>(OnSceSblDriverSendMsg), kdlsym(sceSblKeymgrSetKeyStorage__sceSblDriverSendMsg_hook));
	Utilities::HookFunctionCall(s_TrampolineK, reinterpret_cast<void*>(OnSceSblKeymgrInvalidateKeySxXlock), kdlsym(sceSblKeymgrInvalidateKey__sx_xlock_hook));

	WriteLog(LL_Debug, "Installed fpkg hooks");
}

FakePkgManager::~FakePkgManager()
{

}

bool FakePkgManager::ShellCorePatch()
{
	WriteLog(LL_Debug, "patching SceShellCore");


	struct ::proc* s_Process = Utilities::FindProcessByName("SceShellCore");
	if (s_Process == nullptr)
	{
		WriteLog(LL_Error, "could not find SceShellCore");
		return false;
	}

	ProcVmMapEntry* s_Entries = nullptr;
	size_t s_NumEntries = 0;
	auto s_Ret = Utilities::GetProcessVmMap(s_Process, &s_Entries, &s_NumEntries);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "could not get vm map");
		return false;
	}

	if (s_Entries == nullptr || s_NumEntries == 0)
	{
		WriteLog(LL_Error, "invalid entries (%p) or numEntries (%d)", s_Entries, s_NumEntries);
		return false;
	}

	uint8_t* s_TextStart = nullptr;
	for (auto i = 0; i < s_NumEntries; ++i)
	{
		if (s_Entries[i].prot == (PROT_READ | PROT_EXEC))
		{
			s_TextStart = (uint8_t*)s_Entries[i].start;
			break;
		}
	}

	if (s_TextStart == nullptr)
	{
		WriteLog(LL_Error, "could not find SceShellCore text start");
		return false;
	}

	WriteLog(LL_Debug, "SceShellCore .text: (%p)", s_TextStart);

	// Free the entries we got returned
	delete [] s_Entries;
	s_Entries = nullptr;

	uint8_t xor__eax_eax[5] = { 0x31, 0xC0, 0x90, 0x90, 0x90 };

	/*
	s_Ret = kptrace_t(PT_ATTACH, s_Process->p_pid, 0, 0, s_MainThread);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "could not attach to shellcore");
		return false;
	}

	int32_t s_Status = 0;
	s_Ret = kwait4_t(s_Process->p_pid, &s_Status, WUNTRACED, nullptr, s_MainThread);
	WriteLog(LL_Debug, "wait4 returned (%d)", s_Ret);*/

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_sceKernelIsGenuineCEX_patchA), sizeof(xor__eax_eax), xor__eax_eax, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_sceKernelIsGenuineCEX_patchA");
		return false;
	}

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_sceKernelIsGenuineCEX_patchB), sizeof(xor__eax_eax), xor__eax_eax, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_sceKernelIsGenuineCEX_patchB");
		return false;
	}

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_sceKernelIsGenuineCEX_patchC), sizeof(xor__eax_eax), xor__eax_eax, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_sceKernelIsGenuineCEX_patchC");
		return false;
	}

#if MIRA_PLATFORM > MIRA_PLATFORM_ORBIS_BSD_455
	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_sceKernelIsGenuineCEX_patchD), sizeof(xor__eax_eax), xor__eax_eax, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_sceKernelIsGenuineCEX_patchD");
		return false;
	}
#endif

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_nidf_libSceDipsw_patchA), sizeof(xor__eax_eax), xor__eax_eax, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_nidf_libSceDipsw_patchA");
		return false;
	}

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_nidf_libSceDipsw_patchB), sizeof(xor__eax_eax), xor__eax_eax, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_nidf_libSceDipsw_patchB");
		return false;
	}

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_nidf_libSceDipsw_patchC), sizeof(xor__eax_eax), xor__eax_eax, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_nidf_libSceDipsw_patchC");
		return false;
	}

#if MIRA_PLATFORM > MIRA_PLATFORM_ORBIS_BSD_455
	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_nidf_libSceDipsw_patchD), sizeof(xor__eax_eax), xor__eax_eax, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_nidf_libSceDipsw_patchD");
		return false;
	}
#endif

#if MIRA_PLATFORM == MIRA_PLATFORM_ORBIS_BSD_405 || (MIRA_PLATFORM >= MIRA_PLATFORM_ORBIS_BSD_474 && MIRA_PLATFORM <= MIRA_PLATFORM_ORBIS_BSD_620)
	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_enable_fakepkg_patch), 8, (void*)"\xE9\x96\x00\x00\x00", nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_enable_fakepkg_patch");
		return false;
	}
#elif MIRA_PLATFORM == MIRA_PLATFORM_ORBIS_BSD_455
	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_enable_fakepkg_patch), 8, (void*)"\xE9\x90\x00\x00\x00", nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_enable_fakepkg_patch");
		return false;
	}
#elif MIRA_PLATFORM >= MIRA_PLATFORM_ORBIS_BSD_672
	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_enable_fakepkg_patch), 8, (void*)"\xE9\x98\x00\x00\x00", nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_enable_fakepkg_patch");
		return false;
	}
#endif

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_fake_to_free_patch), 4, (void*)"free", nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_fake_to_free_patch");
		return false;
	}

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_enable_data_mount_patch), 5, (void*)"\x31\xC0\xFF\xC0\x90", nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_enable_data_mount_patch");
		return false;
	}

#if MIRA_PLATFORM >= MIRA_PLATFORM_ORBIS_BSD_450 && MIRA_PLATFORM != MIRA_PLATFORM_ORBIS_BSD_900
	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_external_hdd_pkg_installer_patch), 1, (void*)"\x00", nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_external_hdd_pkg_installer_patch");
		return false;
	}

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_external_hdd_version_patchA), 1, (void*)"\xEB", nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_external_hdd_version_patchA");
		return false;
	}

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_TextStart + ssc_external_hdd_version_patchB), 1, (void*)"\xEB", nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssc_external_hdd_version_patchB");
		return false;
	}

#endif

	/*Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_1_OFFSET), xor__eax_eax, sizeof(xor__eax_eax));
	Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_2_OFFSET), xor__eax_eax, sizeof(xor__eax_eax));
	Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_3_OFFSET), xor__eax_eax, sizeof(xor__eax_eax));
	Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_1_4_OFFSET), xor__eax_eax, sizeof(xor__eax_eax));
	Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_1_OFFSET), xor__eax_eax, sizeof(xor__eax_eax));
	Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_2_OFFSET), xor__eax_eax, sizeof(xor__eax_eax));
	Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_3_OFFSET), xor__eax_eax, sizeof(xor__eax_eax));
	Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_ENABLE_DEBUG_PKG_PATCH_2_4_OFFSET), xor__eax_eax, sizeof(xor__eax_eax));
	Utilities::PtraceIO(s_Process->p_pid, PIOD_WRITE_I, (void*)(s_TextStart + SHELLCORE_USE_FREE_PREFIX_INSTEAD_OF_FAKE_OFFSET), (void*)"free", 4);
	if (kptrace_t(PT_DETACH, s_Process->p_pid, (caddr_t)SIGCONT, 0, s_MainThread) < 0)
	{
		WriteLog(LL_Error, "could not detach from shellcore");
		return false;
	}*/

	WriteLog(LL_Debug, "SceShellCore successfully patched");

	return true;
}

bool FakePkgManager::ShellUIPatch()
{
	WriteLog(LL_Debug, "patching SceShellUI");

	struct ::proc* s_Process = Utilities::FindProcessByName("SceShellUI");
	if (s_Process == nullptr)
	{
		WriteLog(LL_Error, "could not find SceShellUI");
		return false;
	}

	ProcVmMapEntry* s_Entries = nullptr;
	size_t s_NumEntries = 0;
	auto s_Ret = Utilities::GetProcessVmMap(s_Process, &s_Entries, &s_NumEntries);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "could not get vm map");
		return false;
	}

	if (s_Entries == nullptr || s_NumEntries == 0)
	{
		WriteLog(LL_Error, "invalid entries (%p) or numEntries (%d)", s_Entries, s_NumEntries);
		return false;
	}

	uint8_t* s_LibKernelTextStart = nullptr;
	for (auto i = 0; i < s_NumEntries; ++i)
	{
		if (!memcmp(s_Entries[i].name, "libkernel_sys.sprx", 18) && s_Entries[i].prot >= (PROT_READ | PROT_EXEC))
		{
			s_LibKernelTextStart = (uint8_t*)s_Entries[i].start;
			break;
		}
	}

	if (s_LibKernelTextStart == nullptr)
	{
		WriteLog(LL_Error, "could not find SceShellUI libkernel_sys.sprx text start");
		return false;
	}

	WriteLog(LL_Debug, "SceShellUI libkernel_sys.sprx .text: (%p)", s_LibKernelTextStart);

	// Free the entries we got returned
	delete [] s_Entries;
	s_Entries = nullptr;

	// TODO: Fix all fw suport; I don't feel like fixing 1.76 support atm -kd
	#if MIRA_PLATFORM <= MIRA_PLATFORM_ORBIS_BSD_176 || (MIRA_PLATFORM > MIRA_PLATFORM_ORBIS_BSD_702 && MIRA_PLATFORM != MIRA_PLATFORM_ORBIS_BSD_900)
	#else

	uint8_t mov__eax_1__ret[6] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_LibKernelTextStart + ssu_sceSblRcMgrIsAllowDebugMenuForSettings_patch), sizeof(mov__eax_1__ret), mov__eax_1__ret, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssu_sceSblRcMgrIsAllowDebugMenuForSettings_patch");
		return false;
	}

	s_Ret = Utilities::ProcessReadWriteMemory(s_Process, (void*)(s_LibKernelTextStart + ssu_sceSblRcMgrIsStoreMode_patch), sizeof(mov__eax_1__ret), mov__eax_1__ret, nullptr, true);
	if (s_Ret < 0)
	{
		WriteLog(LL_Error, "ssu_sceSblRcMgrIsStoreMode_patch");
		return false;
	}

	#endif

	WriteLog(LL_Debug, "SceShellUI successfully patched");

	return true;
}

void FakePkgManager::ResumeEvent()
{
	ShellUIPatch();
	WriteLog(LL_Debug, "InstallEventHandlers finished");
	return;
}

void FakePkgManager::ProcessStartEvent(void *arg, struct ::proc *p)
{
	auto strncmp = (int(*)(const char *, const char *, size_t))kdlsym(strncmp);

	if (!p)
		return;

	char* s_TitleId = (char*)((uint64_t)p + 0x390);
	if (strncmp(s_TitleId, "NPXS20000", 9) == 0)
		ShellCorePatch();

	if (strncmp(s_TitleId, "NPXS20001", 9) == 0)
		ShellUIPatch();

	return;
}

void* prison0 = nullptr;
void* re_rdir = nullptr;
void* re_jdir = nullptr;

void* sys_jailbreak(struct thread *td) {

    struct ucred* cred = td->td_proc->p_ucred;
    struct filedesc* fd = td->td_proc->p_fd;

    void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	/*WriteLog(LL_Debug, "p_fd = %p\n", fd);
	WriteLog(LL_Debug,"p_proc = %p\n", td->td_proc);
	WriteLog(LL_Debug,"p_ucred = %p\n", td->td_ucred);
	WriteLog(LL_Debug,"cred->cr_uid = %i\n", cred->cr_uid);
	WriteLog(LL_Debug,"cred->cr_ruid = %i\n", cred->cr_ruid);
	WriteLog(LL_Debug," cred->cr_rgid = %i\n",  cred->cr_rgid);
	WriteLog(LL_Debug," cred->cr_groups[0] = %i\n",  cred->cr_groups[0]);
	WriteLog(LL_Debug," sonycred = %lx\n",  (uint64_t *)(((char *)td_ucred) + 96));
	WriteLog(LL_Debug," sonyproctype = %lx\n",  (uint64_t *)(((char *)td_ucred) + 88));
	WriteLog(LL_Debug," sonyproccap = %lx\n", (uint64_t *)(((char *)td_ucred) + 104));*/

    cred->cr_uid = 0;
    cred->cr_ruid = 0;
    cred->cr_rgid = 0;
    cred->cr_groups[0] = 0;
    cred->cr_prison = *(struct prison**)kdlsym(prison0);
    fd->fd_rdir = fd->fd_jdir = *(struct vnode **)kdlsym(rootvnode);

    // sceSblACMgrIsSystemUcred
    uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
    *sonyCred = 0xFFFFFFFFFFFFFFFFULL;

    // sceSblACMgrGetDeviceAccessType
    uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
    *sceProcType = 0x3801000000000013; // Max access

    // sceSblACMgrHasSceProcessCapability
    uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
    *sceProcCap = 0xFFFFFFFFFFFFFFFFULL; // Sce Process

	/*WriteLog(LL_Debug, "After p_fd = %p\n", fd);
	WriteLog(LL_Debug,"After p_proc = %p\n", td->td_proc);
	WriteLog(LL_Debug,"After p_ucred = %p\n", td->td_ucred);
	WriteLog(LL_Debug,"After cred->cr_uid = %i\n", cred->cr_uid);
	WriteLog(LL_Debug," After cred->cr_ruid = %i\n", cred->cr_ruid);
	WriteLog(LL_Debug," After cred->cr_rgid = %i\n",  cred->cr_rgid);
	WriteLog(LL_Debug," After cred->cr_groups[0] = %i\n",  cred->cr_groups[0]);
	WriteLog(LL_Debug," After cred->cr_prison = %p\n",  cred->cr_prison);
	WriteLog(LL_Debug," After sonycred = %lx\n",  (uint64_t *)(((char *)td_ucred) + 96));
	WriteLog(LL_Debug," After sonyproctype = %lx\n",  (uint64_t *)(((char *)td_ucred) + 88));
	WriteLog(LL_Debug," After sonyproccap = %lx\n", (uint64_t *)(((char *)td_ucred) + 104));*/

    td->td_retval[0] = 0;
    return 0;
}

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

// Calculate MD5 hash of a buffer
void md5(uint8_t* initial_msg, uint64_t initial_len, char* md5_final_hash) {
	auto malloc = (void* (*)(unsigned long size, struct malloc_type* type, int flags))kdlsym(malloc);
	auto free = (void(*)(void* addr, struct malloc_type* type))kdlsym(free);
	auto M_TEMP = (struct malloc_type*)kdlsym(M_TEMP);

	// These vars will contain the hash
	uint32_t h0, h1, h2, h3;

	// Message (to prepare)
	uint8_t* msg = NULL;

	// Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating

	// r specifies the per-round shift amounts

	uint32_t r[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
					5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
					4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
					6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

	// Use binary integer part of the sines of integers (in radians) as constants// Initialize variables:
	uint32_t k[] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

	h0 = 0x67452301;
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;

	// Pre-processing: adding a single 1 bit
	//append "1" bit to message    
	/* Notice: the input bytes are considered as bits strings,
	   where the first bit is the most significant bit of the byte.[37] */

	   // Pre-processing: padding with zeros
	   //append "0" bit until message length in bit ≡ 448 (mod 512)
	   //append length mod (2 pow 64) to message

	int new_len = ((((initial_len + 8) / 64) + 1) * 64) - 8;

	msg = (uint8_t*)malloc(new_len + 64, M_TEMP, 2); // also appends "0" bits (we alloc also 64 extra bytes...)
	memset(msg, NULL, new_len + 64);

	memcpy(msg, initial_msg, initial_len);
	msg[initial_len] = 128; // write the "1" bit

	uint32_t bits_len = 8 * initial_len; // note, we append the len
	memcpy(msg + new_len, &bits_len, 4); // in bits at the end of the buffer

	// Process the message in successive 512-bit chunks:
	//for each 512-bit chunk of message:
	int offset;
	for (offset = 0; offset < new_len; offset += (512 / 8)) {

		// break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
		uint32_t* w = (uint32_t*)(msg + offset);

		// Initialize hash value for this chunk:
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;

		// Main loop:
		uint32_t i;
		for (i = 0; i < 64; i++) {

			uint32_t f, g;

			if (i < 16) {
				f = (b & c) | ((~b) & d);
				g = i;
			}
			else if (i < 32) {
				f = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			}
			else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			}
			else {
				f = c ^ (b | (~d));
				g = (7 * i) % 16;
			}

			uint32_t temp = d;
			d = c;
			c = b;
			//printf("rotateLeft(%x + %x + %x + %x, %d)\n", a, f, k[i], w[g], r[i]);
			b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
			a = temp;
		}

		// Add this chunk's hash to result so far:
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
	}

	// cleanup
	free(msg, M_TEMP);

	auto snprintf = (int(*)(char* str, size_t size, const char* format, ...))kdlsym(snprintf);

	// Transform result to MD5 string
	uint8_t* p;
	p = (uint8_t*)&h0;
	snprintf(md5_final_hash + (0x8 * 0), 9, "%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], h0);

	p = (uint8_t*)&h1;
	snprintf(md5_final_hash + (0x8 * 1), 9, "%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], h1);

	p = (uint8_t*)&h2;
	snprintf(md5_final_hash + (0x8 * 2), 9, "%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], h2);

	p = (uint8_t*)&h3;
	snprintf(md5_final_hash + (0x8 * 3), 9, "%2.2x%2.2x%2.2x%2.2x", p[0], p[1], p[2], p[3], h3);

	md5_final_hash[32] = 0;
}

void* get_syscall_function(uint32_t n) {
    auto sv = (struct sysentvec*)kdlsym(self_orbis_sysvec);
    struct sysent *sysents = sv->sv_table;
    
    struct sysent *p = &sysents[n];
    return (void *)p->sy_call;
}

void install_syscall(uint32_t n, void *func) {

    auto sv = (struct sysentvec*)kdlsym(self_orbis_sysvec);
    struct sysent* sysents = sv->sv_table;

    struct sysent *p = &sysents[n];
    memset(p, NULL, sizeof(struct sysent));
    p->sy_narg = 8;
    p->sy_call = (sy_call_t *)func;
    p->sy_thrcnt = 1;
}

void DumpHex(const void *data, size_t size) {
  auto printf = (void(*)(char *format, ...))kdlsym(printf);
        
  size_t i;
  for (i = 0; i < size; i++) {
    printf("%02hhX%c", ((char *)data)[i], (i + 1) % 16 ? ' ' : '\n');
  }
  printf("\n");
}

struct cdev {
    void        *si_spare0;
    unsigned int        si_flags;
    struct timespec    si_atime;
    struct timespec    si_ctime;
    struct timespec    si_mtime;
    uid_t        si_uid;
    gid_t        si_gid;
    mode_t        si_mode;
    struct ucred    *si_cred;    /* cached clone-time credential */
    int        si_drv0;
    int        si_refcount;
    LIST_ENTRY(cdev)    si_list;
    LIST_ENTRY(cdev)    si_clone;
    LIST_HEAD(, cdev) si_children;
    LIST_ENTRY(cdev)    si_siblings;
    struct cdev *si_parent;
    struct mount    *si_mountpt;
    void        *si_drv1, *si_drv2;
    struct cdevsw    *si_devsw;
    int        si_iosize_max;    /* maximum I/O size (for physio &al) */
    unsigned long        si_usecount;
    unsigned long        si_threadcount;
    union {
        struct snapdata *__sid_snapdata;
    } __si_u;
    char        si_name[63 + 1];
};

#define LOG(...)                WriteLog(LL_Debug, __VA_ARGS__)

#define	O_RDONLY	0x0000	

typedef struct _decrypt_header_args
{
	void* buffer;
	uint64_t length;
	int type;
}
decrypt_header_args;

typedef struct _verify_segment_args
{
	uint16_t index;
	void* buffer;
	uint64_t length;
}
verify_segment_args;

typedef struct _decrypt_segment_args
{
	uint16_t index;
	void* buffer;
	uint64_t length;
}
decrypt_segment_args;

typedef struct _decrypt_segment_block_args
{
	uint16_t entry_index;
	uint16_t block_index;
	void* block_buffer;
	uint64_t block_length;
	void* table_buffer;
	uint64_t table_length;
}
decrypt_segment_block_args;

int (*sys_ioctl_orig)(struct thread* td, struct ioctl_args* uap) = NULL;

int sys_ioctl_hook(struct thread *td, struct ioctl_args *uap) {
	auto malloc = (void* (*)(unsigned long size, struct malloc_type* type, int flags))kdlsym(malloc);
	auto free = (void(*)(void* addr, struct malloc_type* type))kdlsym(free);
	auto M_TEMP = (struct malloc_type*)kdlsym(M_TEMP);
	auto printf = (void(*)(char* format, ...))kdlsym(printf);
	auto snprintf = (int(*)(char* str, size_t size, const char* format, ...))kdlsym(snprintf);
	auto copyin = (int(*)(const void* uaddr, void* kaddr, size_t len))kdlsym(copyin);
	auto copyout = (int(*)(const void* kaddr, void* udaddr, size_t len))kdlsym(copyout);

	// patch out any functionality
    switch (uap->com) {
        case 0xFFFFFFFF2000440C: // write_app_pup_info
        case 0x2000440C : { 
			LOG("IOCTL(0x2000440C): write_app_pup_info called.\n");
			LOG("IOCTL(0x2000440C): uap->fd: 0x%x\n", uap->fd);
			LOG("IOCTL(0x2000440C): uap->com: 0x%x\n", uap->com);
			LOG("IOCTL(0x2000440C): uap->data: 0x%x\n", uap->data);
			if (uap->data) {
				DumpHex(uap->data, 32);
			}
            break;
        };  

        case 0xFFFFFFFF20004407: // switch_bank
        case 0x20004407 : { 
            LOG("IOCTL(0x20004407): switch_bank called.\n");
            LOG("IOCTL(0x20004407): uap->fd: 0x%x\n", uap->fd);
            LOG("IOCTL(0x20004407): uap->com: 0x%x\n", uap->com);
            LOG("IOCTL(0x20004407): uap->data: 0x%x\n", uap->data);
            
            LOG("s_state_2:\n");
            DumpHex((void*)&gKernelBase[0x2684218], 24);
            
            // cpu_vaddr
            //LOG("s_buff_2:\n");
            //DumpHex((void*)&gKernelBase[0x2688000], 16384);
            
            uint64_t gpu_paddr = *(uint64_t*)&gKernelBase[0x2684250];
            LOG("gpu_paddr: 0x%x\n", gpu_paddr);
            
            //LOG("Entire Dump\n");
            //DumpHex((void*)&gKernelBase[0x2684218], 0xC224);
                        
            LOG("IOCTL(0x20004407): td->td_tid = 0x%x\n", td->td_tid);
            
			LOG("IOCTL(0x20004407): random_bool_1 = 0x%x\n", *(int*)&gKernelBase[0x2690000]);
			LOG("IOCTL(0x20004407): random_bool_2 = 0x%x\n", *(int*)&gKernelBase[0x2690004]);
			LOG("IOCTL(0x20004407): random_bool_3 = 0x%x\n", *(int*)&gKernelBase[0x2690008]);
			LOG("IOCTL(0x20004407): s_emcSwitched_b = 0x%x\n", *(int*)&gKernelBase[0x269000C]);
			LOG("IOCTL(0x20004407): s_socSwitched_b = 0x%x\n", *(int*)&gKernelBase[0x2690010]);

            break;
        };        

		case 0xFFFFFFFFC0184401: // Decrypt PUP Header
		case 0xC0184401: { 
			// Copy argument
			decrypt_header_args header_args;
			copyin(uap->data, (void*)&header_args, sizeof(decrypt_header_args));

			// Copy buffer and remplace the uaddr by an kaddr
			void* buffer_uap = header_args.buffer;
			void* buffer = malloc(header_args.length, M_TEMP, 2); // also appends "0" bits (we alloc also 64 extra bytes...)
			memset(buffer, NULL, header_args.length);
			copyin(buffer_uap, buffer, header_args.length);
			header_args.buffer = buffer;

			// Create the MD5 digest of the PUP Header
			char md5_data[33];
			md5((uint8_t*)header_args.buffer, header_args.length, md5_data);

			printf("IOCTL(0xC0184401): Decrypt PUP Header called.\n");
			printf("MD5: %s\n", md5_data);

			char file[255];
			snprintf(file, 255, "/mnt/usb0/decrypt/%s.dec", md5_data);

			int fd = kopen_t(file, O_RDONLY, 0777, curthread);
			if (fd) {
				long file_size = klseek_t(fd, 0, 2, curthread);
				klseek_t(fd, 0, 0, curthread);

				printf("file: %s - fd: %i - size: %ld\n", file, fd, file_size);

				void* file_buffer = malloc(file_size, M_TEMP, 2);
				kread_t(fd, file_buffer, file_size, curthread);
				kclose_t(fd, curthread);

				copyout(file_buffer, buffer_uap, file_size);
				printf("Returning fake decrypted data done.\n");

				free(file_buffer, M_TEMP);
				free(header_args.buffer, M_TEMP);
				header_args.buffer = buffer_uap;

				td->td_retval[0] = 0;
				return 0;
			}

			printf("Calling original decrypt function ...\n");

			// Clean memory
			free(header_args.buffer, M_TEMP);
			header_args.buffer = buffer_uap;
			break;
		};

		case 0xFFFFFFFFC0184402: // Verify segment (1)
		case 0xC0184402: { 
			printf("IOCTL(0xC0184402): Verify segment (1) called.\n");
			td->td_retval[0] = (int)0;
			return (int)0; // Alway tell OK
			break;
		};

		case 0xFFFFFFFFC0184403: // Verify segment (2)
		case 0xC0184403: { 
			printf("IOCTL(0xC0184403): Verify segment (2) called.\n");
			td->td_retval[0] = (int)0;
			return (int)0; // Alway tell OK
			break;
		};

		case 0xFFFFFFFFC010440D: // Verify BLS Header (3)
		case 0xC010440D: { 
			printf("IOCTL(0xC010440D): Verify BLS Header (3) called.\n");
			td->td_retval[0] = (int)0;
			return (int)0; // Alway tell OK
			break;
		}

		case 0xFFFFFFFFC0184404: // Decrypt segment
		case 0xC0184404: { 
			// Copy argument
			decrypt_segment_args decrypt_args;
			copyin(uap->data, (void*)&decrypt_args, sizeof(decrypt_segment_args));

			// Copy buffer and remplace the uaddr by an kaddr
			void* buffer_uap = decrypt_args.buffer;
			void* buffer = malloc(decrypt_args.length, M_TEMP, 2); // also appends "0" bits (we alloc also 64 extra bytes...)
			memset(buffer, NULL, decrypt_args.length);
			copyin(buffer_uap, buffer, decrypt_args.length);
			decrypt_args.buffer = buffer;

			// Create the MD5 digest of the PUP Header
			char md5_data[33];
			md5((uint8_t*)decrypt_args.buffer, decrypt_args.length, md5_data);

			printf("IOCTL(0xC0184404): Decrypt segment called.\n");
			printf("MD5: %s\n", md5_data);

			char file[255];
			snprintf(file, 255, "/mnt/usb0/decrypt/%s.dec", md5_data);

			int fd = kopen_t(file, O_RDONLY, 0777, curthread);
			if (fd) {
				long file_size = klseek_t(fd, 0, 2, curthread);
				klseek_t(fd, 0, 0, curthread);

				printf("file: %s - fd: %i - size: %ld\n", file, fd, file_size);

				void* file_buffer = malloc(file_size, M_TEMP, 2);
				kread_t(fd, file_buffer, file_size, curthread);
				kclose_t(fd, curthread);

				copyout(file_buffer, buffer_uap, file_size);
				printf("Returning fake decrypted data done.\n");

				free(file_buffer, M_TEMP);
				free(decrypt_args.buffer, M_TEMP);
				decrypt_args.buffer = buffer_uap;
				td->td_retval[0] = 0;
				return 0;
			}

			printf("Calling original decrypt function ...\n");

			// Clean memory
			free(decrypt_args.buffer, M_TEMP);
			decrypt_args.buffer = buffer_uap;
			break;
		};

		case 0xFFFFFFFFC0284405: // Decrypt segment block
		case 0xC0284405: { 
			// Copy argument
			decrypt_segment_block_args decrypt_block_args;
			copyin(uap->data, (void*)&decrypt_block_args, sizeof(decrypt_segment_block_args));

			// Copy buffer and remplace the uaddr by an kaddr
			void* block_buffer_uap = decrypt_block_args.block_buffer;
			void* block_buffer = malloc(decrypt_block_args.block_length, M_TEMP, 2); // also appends "0" bits (we alloc also 64 extra bytes...)
			memset(block_buffer, NULL, decrypt_block_args.block_length);
			copyin(block_buffer_uap, block_buffer, decrypt_block_args.block_length);

			// Create the MD5 digest of the PUP Header
			char md5_data[33];
			md5((uint8_t*)block_buffer, decrypt_block_args.block_length, md5_data);

			printf("IOCTL(0xC0284405): Decrypt segment block called.\n");
			printf("MD5: %s\n", md5_data);

			char file[255];
			snprintf(file, 255, "/mnt/usb0/decrypt/%s.dec", md5_data);

			int fd = kopen_t(file, O_RDONLY, 0777, curthread);
			if (fd) {
				long file_size = klseek_t(fd, 0, 2, curthread);
				klseek_t(fd, 0, 0, curthread);

				printf("file: %s - fd: %i - size: %ld\n", file, fd, file_size);

				void* file_buffer = malloc(file_size, M_TEMP, 2);
				kread_t(fd, file_buffer, file_size, curthread);
				kclose_t(fd, curthread);

				copyout(file_buffer, block_buffer_uap, file_size);
				printf("Returning fake decrypted data done.\n");

				free(file_buffer, M_TEMP);
				free(block_buffer, M_TEMP);
				td->td_retval[0] = 0;
				return 0;
			}

			printf("Calling original decrypt function ...\n");

			// Clean memory
			free(block_buffer, M_TEMP);
			break;
		};
    }
    
	// call the original command handler
    int ret = sys_ioctl_orig(td, uap);

	// dump things after the original ioctl command has been called (useful debugging)
    if (uap->com == 0xFFFFFFFF20004407 || uap->com ==  0x20004407) {        
		LOG("IOCTL(0x%X): ret = %x\n", uap->com, ret);
		LOG("IOCTL(0x%X): td->td_retval[0] = %x\n", uap->com, td->td_retval[0]);

        // cpu_vaddr
        //LOG("s_buff_2:\n");
        //DumpHex((void*)&gKernelBase[0x2688000], 16384);
    
        //LOG("Entire Dump\n");
        //DumpHex((void*)&gKernelBase[0x2684218], 0xC224);
    }

    return ret;
}

bool FakePkgManager::OnLoad()
{
	auto s_MainThread = Mira::Framework::GetFramework()->GetMainThread();
	if (s_MainThread == nullptr)
	{
		WriteLog(LL_Error, "could not get main mira thread");
		return false;
	}

	ShellCorePatch();
	ShellUIPatch();

	// Initialize the event handlers
	auto eventhandler_register = (eventhandler_tag(*)(struct eventhandler_list *list, const char *name, void *func, void *arg, int priority))kdlsym(eventhandler_register);

	m_processStartEvent = eventhandler_register(NULL, "process_exec_end", reinterpret_cast<void*>(FakePkgManager::ProcessStartEvent), NULL, EVENTHANDLER_PRI_LAST);
	m_resumeEvent = eventhandler_register(NULL, "system_resume_phase4", reinterpret_cast<void*>(FakePkgManager::ResumeEvent), NULL, EVENTHANDLER_PRI_LAST);

	// 0. Install the jailbreak
	install_syscall(9, (void*)sys_jailbreak);
	
	// 1. Resolve syscall functions
	sys_ioctl_orig = (int (*)(struct thread *, struct ioctl_args *))get_syscall_function(54);
	
	// 2. Install the Ioctl hook
	install_syscall(54, (void*)sys_ioctl_hook);

    WriteLog(LL_Error, "Installed ioctl hook\n");
        
	return true;
}

bool FakePkgManager::OnUnload()
{
	auto eventhandler_deregister = (void(*)(struct eventhandler_list* a, struct eventhandler_entry* b))kdlsym(eventhandler_deregister);
	auto eventhandler_find_list = (struct eventhandler_list * (*)(const char *name))kdlsym(eventhandler_find_list);

	if (m_processStartEvent) {
		EVENTHANDLER_DEREGISTER(process_exec_end, m_processStartEvent);
		m_processStartEvent = nullptr;
	}

	if (m_resumeEvent) {
		EVENTHANDLER_DEREGISTER(process_exit, m_resumeEvent);
		m_resumeEvent = nullptr;
	}

	return true;
}

bool FakePkgManager::OnSuspend()
{
	return true;
}

bool FakePkgManager::OnResume()
{
	return true;
}

void FakePkgManager::GenPfsCryptoKey(uint8_t* p_EncryptionKeyPFS, uint8_t p_Seed[PFS_SEED_SIZE], uint32_t p_Index, uint8_t p_Key[PFS_FINAL_KEY_SIZE])
{
	auto s_Thread = curthread;
	FakeKeyD s_D;
	memset(&s_D, 0, sizeof(s_D));

	s_D.index = p_Index;
	memcpy(s_D.seed, p_Seed, PFS_SEED_SIZE);

	// fpu_kern_enter
	auto fpu_kern_enter = (int(*)(struct thread *td, struct fpu_kern_ctx *ctx, u_int flags))kdlsym(fpu_kern_enter);
	auto fpu_kern_leave = (int (*)(struct thread *td, struct fpu_kern_ctx *ctx))kdlsym(fpu_kern_leave);

	auto fpu_ctx = (fpu_kern_ctx*)kdlsym(fpu_kern_ctx);
	auto Sha256Hmac = (void (*)(uint8_t hash[0x20], const uint8_t* data, size_t data_size, const uint8_t* key, int key_size))kdlsym(Sha256Hmac);

	fpu_kern_enter(s_Thread, fpu_ctx, 0);
	Sha256Hmac(p_Key, (const uint8_t*)&s_D, sizeof(s_D), p_EncryptionKeyPFS, EKPFS_SIZE);
	fpu_kern_leave(s_Thread, fpu_ctx);
}

void FakePkgManager::GenPfsEncKey(uint8_t* p_EncryptionKeyPFS, uint8_t p_Seed[PFS_SEED_SIZE], uint8_t p_Key[PFS_FINAL_KEY_SIZE])
{
	GenPfsCryptoKey(p_EncryptionKeyPFS, p_Seed, 1, p_Key);
}

void FakePkgManager::GenPfsSignKey(uint8_t* p_EncryptionKeyPFS, uint8_t p_Seed[PFS_SEED_SIZE], uint8_t p_Key[PFS_FINAL_KEY_SIZE])
{
	GenPfsCryptoKey(p_EncryptionKeyPFS, p_Seed, 2, p_Key);
}

int FakePkgManager::DecryptNpdrmDebugRif(uint32_t p_Type, uint8_t* p_Data)
{
	auto s_Thread = __curthread();
	if (s_Thread == nullptr)
		return SCE_SBL_ERROR_NPDRM_ENOTSUP;

	auto fpu_kern_enter = (int(*)(struct thread *td, struct fpu_kern_ctx *ctx, u_int flags))kdlsym(fpu_kern_enter);
	auto fpu_kern_leave = (int (*)(struct thread *td, struct fpu_kern_ctx *ctx))kdlsym(fpu_kern_leave);
	auto fpu_ctx = (fpu_kern_ctx*)kdlsym(fpu_kern_ctx);
	//auto AesCbcCfb128Encrypt = (int (*)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv))kdlsym(AesCbcCfb128Encrypt);
	auto AesCbcCfb128Decrypt = (int (*)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv))kdlsym(AesCbcCfb128Decrypt);

	auto s_Ret = 0;
	fpu_kern_enter(s_Thread, fpu_ctx, 0);
	s_Ret = AesCbcCfb128Decrypt(p_Data + RIF_DIGEST_SIZE, p_Data + RIF_DIGEST_SIZE, RIF_DATA_SIZE, g_RifDebugKey, sizeof(g_RifDebugKey) * 8, p_Data);
	fpu_kern_leave(s_Thread, fpu_ctx);
	if (s_Ret)
		return SCE_SBL_ERROR_NPDRM_ENOTSUP;

	return s_Ret;
}

SblMapListEntry* FakePkgManager::SceSblDriverFindMappedPageListByGpuVa(vm_offset_t p_GpuVa)
{
	if (p_GpuVa == 0)
	{
		WriteLog(LL_Error, "invalid gpu va");
		return nullptr;
	}

	auto _mtx_lock_flags = (void(*)(struct mtx *m, int opts, const char *file, int line))kdlsym(_mtx_lock_flags);
	auto _mtx_unlock_flags = (void(*)(struct mtx *m, int opts, const char *file, int line))kdlsym(_mtx_unlock_flags);
	auto s_SblDrvMsgMtx = (struct mtx*)kdlsym(sbl_drv_msg_mtx);

	SblMapListEntry* s_Entry = *(SblMapListEntry**)kdlsym(gpu_va_page_list);
	SblMapListEntry* s_FinalEntry = nullptr;

	// Lock before we iterate this list, because other paths can absolutely use it concurrently
	_mtx_lock_flags(s_SblDrvMsgMtx, 0, __FILE__, __LINE__);

	while (s_Entry)
	{
		if (s_Entry->gpuVa == p_GpuVa)
		{
			s_FinalEntry = s_Entry;
			break;
		}

		s_Entry = s_Entry->next;
	}

	_mtx_unlock_flags(s_SblDrvMsgMtx, 0, __FILE__, __LINE__);
	return s_FinalEntry;
}

vm_offset_t FakePkgManager::SceSblDriverGpuVaToCpuVa(vm_offset_t p_GpuVa, size_t* p_NumPageGroups)
{
	auto s_Entry = SceSblDriverFindMappedPageListByGpuVa(p_GpuVa);
	if (s_Entry == nullptr)
		return 0;

	if (p_NumPageGroups != nullptr)
		*p_NumPageGroups = s_Entry->numPageGroups;

	return s_Entry->cpuVa;
}


int FakePkgManager::OnSceSblDriverSendMsg(SblMsg* p_Message, size_t p_Size) __attribute__ ((optnone))
{
	auto sceSblDriverSendMsg = (int (*)(SblMsg* msg, size_t size))kdlsym(sceSblDriverSendMsg);
	if (p_Message->hdr.cmd != SBL_MSG_CCP)
		return sceSblDriverSendMsg(p_Message, p_Size);

	union ccp_op* s_Op = &p_Message->service.ccp.op;
	if (CCP_OP(s_Op->common.cmd) != CCP_OP_AES)
		return sceSblDriverSendMsg(p_Message, p_Size);

	uint32_t s_Mask = CCP_USE_KEY_FROM_SLOT | CCP_GENERATE_KEY_AT_SLOT;
	if ((s_Op->aes.cmd & s_Mask) != s_Mask || (s_Op->aes.key_index != PFS_FAKE_OBF_KEY_ID))
		return sceSblDriverSendMsg(p_Message, p_Size);

	s_Op->aes.cmd &= ~CCP_USE_KEY_FROM_SLOT;

	size_t key_len = 16;

	/* reverse key bytes */
	//WriteLog(LL_Debug, "before");
	for (auto i = 0; i < key_len; ++i)
		s_Op->aes.key[i] = g_FakeKeySeed[key_len - i - 1];
	//WriteLog(LL_Debug, "after");

	return sceSblDriverSendMsg(p_Message, p_Size);
}

int FakePkgManager::OnSceSblPfsSetKeys(uint32_t* ekh, uint32_t* skh, uint8_t* eekpfs, Ekc* eekc, uint32_t pubkey_ver, uint32_t key_ver, PfsHeader* hdr, size_t hdr_size, uint32_t type, uint32_t finalized, uint32_t is_disc)
{
	auto sceSblPfsSetKeys = (int(*)(uint32_t* p_Ekh, uint32_t* p_Skh, uint8_t* p_Eekpfs, Ekc* p_Eekc, unsigned int p_PubkeyVer, unsigned int p_KeyVer, PfsHeader* p_Header, size_t p_HeaderSize, unsigned int p_Type, unsigned int p_Finalized, unsigned int p_IsDisc))kdlsym(sceSblPfsSetKeys);
	auto RsaesPkcs1v15Dec2048CRT = (int (*)(RsaBuffer* out, RsaBuffer* in, RsaKey* key))kdlsym(RsaesPkcs1v15Dec2048CRT);
	auto fpu_kern_enter = (int(*)(struct thread *td, struct fpu_kern_ctx *ctx, u_int flags))kdlsym(fpu_kern_enter);
	auto fpu_kern_leave = (int (*)(struct thread *td, struct fpu_kern_ctx *ctx))kdlsym(fpu_kern_leave);
	auto sbl_pfs_sx = (struct sx*)kdlsym(sbl_pfs_sx);
	auto fpu_kern_ctx = (struct fpu_kern_ctx*)kdlsym(fpu_kern_ctx);
	//int	(*A_sx_xlock_hard)(struct sx *sx, uintptr_t tid, int opts, const char *file, int line) = kdlsym(_sx_xlock);
	//void (*A_sx_xunlock_hard)(struct sx *sx, uintptr_t tid, const char *file, int line) = kdlsym(_sx_xunlock);
	auto A_sx_xlock_hard = (int (*)(struct sx *sx, int opts))kdlsym(_sx_xlock);
	auto A_sx_xunlock_hard = (int (*)(struct sx *sx))kdlsym(_sx_xunlock);
	auto AesCbcCfb128Encrypt = (int (*)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv))kdlsym(AesCbcCfb128Encrypt);
	auto sceSblKeymgrSetKeyForPfs = (int (*)(SblKeyDesc* key, unsigned int* handle))kdlsym(sceSblKeymgrSetKeyForPfs);
	auto sceSblKeymgrClearKey = (int (*)(uint32_t kh))kdlsym(sceSblKeymgrClearKey);

	struct thread* td;
	RsaBuffer in_data;
	RsaBuffer out_data;
	RsaKey key;
	uint8_t ekpfs[EKPFS_SIZE];
	uint8_t iv[16];
	SblKeyDesc enc_key_desc;
	SblKeyDesc sign_key_desc;
	int32_t ret, orig_ret = 0;

	ret = orig_ret = sceSblPfsSetKeys(ekh, skh, eekpfs, eekc, pubkey_ver, key_ver, hdr, hdr_size, type, finalized, is_disc);

	if (ret) {
		if (finalized && is_disc != 0)
		{
			ret = sceSblPfsSetKeys(ekh, skh, eekpfs, eekc, pubkey_ver, key_ver, hdr, hdr_size, type, finalized, 0); /* always use is_disc=0 here */
			if (ret) {
				ret = orig_ret;
				goto err;
			}
		} else {
			memset(&in_data, 0, sizeof(in_data));
			in_data.ptr = eekpfs;
			in_data.size = EEKPFS_SIZE;

			memset(&out_data, 0, sizeof(out_data));
			out_data.ptr = ekpfs;
			out_data.size = EKPFS_SIZE;

			memset(&key, 0, sizeof(key));
			key.p = (uint8_t*)g_ypkg_p;
			key.q = (uint8_t*)g_ypkg_q;
			key.dmp1 = (uint8_t*)g_ypkg_dmp1;
			key.dmq1 = (uint8_t*)g_ypkg_dmq1;
			key.iqmp = (uint8_t*)g_ypkg_iqmp;

			td = curthread;

			fpu_kern_enter(td, fpu_kern_ctx, 0);
			{
				ret = RsaesPkcs1v15Dec2048CRT(&out_data, &in_data, &key);
			}
			fpu_kern_leave(td, fpu_kern_ctx);

			if (ret) {
				ret = orig_ret;
				goto err;
			}

			A_sx_xlock_hard(sbl_pfs_sx,0);
			{
				memset(&enc_key_desc, 0, sizeof(enc_key_desc));
				{
					enc_key_desc.Pfs.obfuscatedKeyId = PFS_FAKE_OBF_KEY_ID;
					enc_key_desc.Pfs.keySize = sizeof(enc_key_desc.Pfs.escrowedKey);

					GenPfsEncKey(ekpfs, hdr->cryptSeed, enc_key_desc.Pfs.escrowedKey);

					fpu_kern_enter(td, fpu_kern_ctx, 0);
					{
						memset(iv, 0, sizeof(iv));
						ret = AesCbcCfb128Encrypt(enc_key_desc.Pfs.escrowedKey, enc_key_desc.Pfs.escrowedKey, sizeof(enc_key_desc.Pfs.escrowedKey), g_FakeKeySeed, sizeof(g_FakeKeySeed) * 8, iv);
					}
					fpu_kern_leave(td, fpu_kern_ctx);
				}
				if (ret) {
					WriteLog(LL_Error, "AesCbcCfb128Encrypt returned (%d)", ret);
					A_sx_xunlock_hard(sbl_pfs_sx);
					ret = orig_ret;
					goto err;
				}

				memset(&sign_key_desc, 0, sizeof(sign_key_desc));
				{
					sign_key_desc.Pfs.obfuscatedKeyId = PFS_FAKE_OBF_KEY_ID;
					sign_key_desc.Pfs.keySize = sizeof(sign_key_desc.Pfs.escrowedKey);

					GenPfsSignKey(ekpfs, hdr->cryptSeed, sign_key_desc.Pfs.escrowedKey);

					fpu_kern_enter(td, fpu_kern_ctx, 0);
					{
						memset(iv, 0, sizeof(iv));
						ret = AesCbcCfb128Encrypt(sign_key_desc.Pfs.escrowedKey, sign_key_desc.Pfs.escrowedKey, sizeof(sign_key_desc.Pfs.escrowedKey), g_FakeKeySeed, sizeof(g_FakeKeySeed) * 8, iv);
					}
					fpu_kern_leave(td, fpu_kern_ctx);
				}
				if (ret) {
					WriteLog(LL_Error, "AesCbcCfb128Encrypt returned (%d).", ret);
					A_sx_xunlock_hard(sbl_pfs_sx);
					ret = orig_ret;
					goto err;
				}

				ret = sceSblKeymgrSetKeyForPfs(&enc_key_desc, ekh);
				if (ret) {
					if (*ekh != 0xFFFFFFFF)
						sceSblKeymgrClearKey(*ekh);

					A_sx_xunlock_hard(sbl_pfs_sx);
					ret = orig_ret;
					goto err;
				}

				ret = sceSblKeymgrSetKeyForPfs(&sign_key_desc, skh);
				if (ret) {
					if (*skh != 0xFFFFFFFF)
						sceSblKeymgrClearKey(*skh);
					A_sx_xunlock_hard(sbl_pfs_sx);
					ret = orig_ret;
					goto err;
				}
			}
			A_sx_xunlock_hard(sbl_pfs_sx);
		}
	}

err:
	return ret;

	/*
	auto sceSblPfsSetKeys = (int(*)(uint32_t* p_Ekh, uint32_t* p_Skh, uint8_t* p_Eekpfs, Ekc* p_Eekc, unsigned int p_PubkeyVer, unsigned int p_KeyVer, PfsHeader* p_Header, size_t p_HeaderSize, unsigned int p_Type, unsigned int p_Finalized, unsigned int p_IsDisc))kdlsym(sceSblPfsSetKeys);

	// Call original function, if it succeeds it's not fake signed
	int s_Ret = sceSblPfsSetKeys(p_Ekh, p_Skh, p_EekPfs, p_Eekc, p_PubKeyVersion, p_KeyVersion, p_Header, p_HeaderSize, p_Type, p_Finalized, p_IsDisc);
	int s_OriginalRet = s_Ret;
	if (s_Ret == 0)
	{
		WriteLog(LL_Error, "sceSblPfsSetKeys returned (%x).", s_Ret);
		return s_Ret;
	}

	if (p_Finalized && p_IsDisc != 0)


	uint8_t s_Ekpfs[EKPFS_SIZE] = { 0 };
	RsaBuffer s_InData
	{
		.ptr = s_Ekpfs,
		.size = EEKPFS_SIZE
	};
	RsaBuffer s_OutData
	{
		.ptr = s_Ekpfs,
		.size = EKPFS_SIZE
	};

	RsaKey s_Key;
	memset(&s_Key, 0, sizeof(s_Key));
	s_Key.p = (uint8_t*)g_ypkg_p;
	s_Key.q = (uint8_t*)g_ypkg_q;
	s_Key.dmp1 = (uint8_t*)g_ypkg_dmp1;
	s_Key.dmq1 = (uint8_t*)g_ypkg_dmq1;
	s_Key.iqmp = (uint8_t*)g_ypkg_iqmp;

	auto s_Thread = __curthread();
	auto RsaesPkcs1v15Dec2048CRT = (int (*)(RsaBuffer* out, RsaBuffer* in, RsaKey* key))kdlsym(RsaesPkcs1v15Dec2048CRT);
	auto fpu_kern_enter = (int(*)(struct thread *td, struct fpu_kern_ctx *ctx, u_int flags))kdlsym(fpu_kern_enter);
	auto fpu_kern_leave = (int (*)(struct thread *td, struct fpu_kern_ctx *ctx))kdlsym(fpu_kern_leave);
	auto sbl_pfs_sx = (struct sx*)kdlsym(sbl_pfs_sx);

	auto fpu_ctx = (fpu_kern_ctx*)kdlsym(fpu_kern_ctx);

	fpu_kern_enter(s_Thread, fpu_ctx, 0);
	s_Ret = RsaesPkcs1v15Dec2048CRT(&s_OutData, &s_InData, &s_Key);
	fpu_kern_leave(s_Thread, fpu_ctx);

	if (s_Ret)
	{
		WriteLog(LL_Error, "RsaesPkcs1v15Dec2048CRT returned (%x).", s_Ret);
		return s_OriginalRet;
	}

	auto _sx_xlock = (int (*)(struct sx *sx, int opts))kdlsym(_sx_xlock);
	auto _sx_xunlock = (int (*)(struct sx *sx))kdlsym(_sx_xunlock);

	//auto _sx_xlock_hard = (int(*)(struct sx *sx, uintptr_t tid, int opts, const char *file, int line))kdlsym(_sx_xlock);
	//auto _sx_xunlock_hard = (int(*)(struct sx *sx, uintptr_t tid, const char *file, int line))kdlsym(_sx_xunlock);
	auto AesCbcCfb128Encrypt = (int (*)(uint8_t* out, const uint8_t* in, size_t data_size, const uint8_t* key, int key_size, uint8_t* iv))kdlsym(AesCbcCfb128Encrypt);

	_sx_xlock(sbl_pfs_sx, 0);

	SblKeyDesc s_EncKeyDesc;
	memset(&s_EncKeyDesc, 0, sizeof(s_EncKeyDesc));

	s_EncKeyDesc.Pfs.obfuscatedKeyId = PFS_FAKE_OBF_KEY_ID;
	s_EncKeyDesc.Pfs.keySize = sizeof(s_EncKeyDesc.Pfs.escrowedKey);

	GenPfsEncKey(s_Ekpfs, p_Header->cryptSeed, s_EncKeyDesc.Pfs.escrowedKey);

	uint8_t s_Iv[16];
	memset(&s_Iv, 0, sizeof(s_Iv));

	fpu_kern_enter(s_Thread, fpu_ctx, 0);
	s_Ret = AesCbcCfb128Encrypt(s_EncKeyDesc.Pfs.escrowedKey, s_EncKeyDesc.Pfs.escrowedKey, sizeof(s_EncKeyDesc.Pfs.escrowedKey), g_FakeKeySeed, sizeof(g_FakeKeySeed) * 8, s_Iv);
	fpu_kern_leave(s_Thread, fpu_ctx);

	if (s_Ret)
	{
		WriteLog(LL_Error, "AesCbcCfb128Encrypt returned (%x)", s_Ret);
		_sx_xunlock(sbl_pfs_sx);
		return s_OriginalRet;
	}

	SblKeyDesc s_SignKeyDesc;
	memset(&s_SignKeyDesc, 0, sizeof(s_SignKeyDesc));

	s_SignKeyDesc.Pfs.obfuscatedKeyId = PFS_FAKE_OBF_KEY_ID;
	s_SignKeyDesc.Pfs.keySize = sizeof(s_SignKeyDesc.Pfs.escrowedKey);

	GenPfsSignKey(s_Ekpfs, p_Header->cryptSeed, s_SignKeyDesc.Pfs.escrowedKey);
	memset(&s_Iv, 0, sizeof(s_Iv));

	fpu_kern_enter(s_Thread, fpu_ctx, 0);
	s_Ret = AesCbcCfb128Encrypt(s_SignKeyDesc.Pfs.escrowedKey, s_SignKeyDesc.Pfs.escrowedKey, sizeof(s_SignKeyDesc.Pfs.escrowedKey), g_FakeKeySeed, sizeof(g_FakeKeySeed) * 8, s_Iv);
	fpu_kern_leave(s_Thread, fpu_ctx);

	if (s_Ret)
	{
		WriteLog(LL_Error, "AesCbcCfb128Encrypt returned (%x).", s_Ret);
		_sx_xunlock(sbl_pfs_sx);
		return s_OriginalRet;
	}

	auto sceSblKeymgrSetKeyForPfs = (int (*)(SblKeyDesc* key, unsigned int* handle))kdlsym(sceSblKeymgrSetKeyForPfs);
	auto sceSblKeymgrClearKey = (int (*)(uint32_t kh))kdlsym(sceSblKeymgrClearKey);

	s_Ret = sceSblKeymgrSetKeyForPfs(&s_EncKeyDesc, p_Ekh);
	if (s_Ret)
	{
		if (*p_Ekh != -1)
			sceSblKeymgrClearKey(*p_Ekh);

		_sx_xunlock(sbl_pfs_sx);
		return s_OriginalRet;
	}

	s_Ret = sceSblKeymgrSetKeyForPfs(&s_SignKeyDesc, p_Skh);
	if (s_Ret)
	{
		if (*p_Skh != -1)
			sceSblKeymgrClearKey(*p_Skh);

		_sx_xunlock(sbl_pfs_sx);
		return s_OriginalRet;
	}

	_sx_xunlock(sbl_pfs_sx);
	return 0;*/
}

int FakePkgManager::OnNpdrmDecryptIsolatedRif(KeymgrPayload* p_Payload)
{
	auto sceSblKeymgrSmCallfunc = (int (*)(KeymgrPayload* payload))kdlsym(sceSblKeymgrSmCallfunc);

	// it's SM request, thus we have the GPU address here, so we need to convert it to the CPU address
	KeymgrRequest* s_Request = reinterpret_cast<KeymgrRequest*>(SceSblDriverGpuVaToCpuVa(p_Payload->data, nullptr));

	// // try to decrypt rif normally
	int s_Ret = sceSblKeymgrSmCallfunc(p_Payload);
	if ((s_Ret != 0 || p_Payload->status != 0) && s_Request)
	{
		if (s_Request->DecryptRif.type == 0x200)
		{
			// fake?
			s_Ret = DecryptNpdrmDebugRif(s_Request->DecryptRif.type, s_Request->DecryptRif.data);
			p_Payload->status = s_Ret;
			s_Ret = 0;
		}
	}

	return s_Ret;
}

int FakePkgManager::OnNpdrmDecryptRifNew(KeymgrPayload* p_Payload)
{
	auto sceSblKeymgrSmCallfunc = (int (*)(KeymgrPayload* payload))kdlsym(sceSblKeymgrSmCallfunc);

	// it's SM request, thus we have the GPU address here, so we need to convert it to the CPU address
	uint64_t s_BufferGpuVa = p_Payload->data;
	auto s_Request = reinterpret_cast<KeymgrRequest*>(SceSblDriverGpuVaToCpuVa(s_BufferGpuVa, nullptr));
	auto s_Response = reinterpret_cast<KeymgrResponse*>(s_Request);

	// try to decrypt rif normally
	int s_Ret = sceSblKeymgrSmCallfunc(p_Payload);
	int s_OriginalRet = s_Ret;

	// and if it fails then we check if it's fake rif and try to decrypt it by ourselves
	if ((s_Ret != 0 || p_Payload->status != 0) && s_Request)
	{
		if (s_Request->DecryptEntireRif.rif.format != 2)
		{
			// not fake?
			goto err;
		}

		s_Ret = DecryptNpdrmDebugRif(s_Request->DecryptEntireRif.rif.format, s_Request->DecryptEntireRif.rif.digest);

		if (s_Ret)
		{
			s_Ret = s_OriginalRet;
			goto err;
		}

		/* XXX: sorry, i'm lazy to refactor this crappy code :D basically, we're copying decrypted data to proper place,
		consult with kernel code if offsets needs to be changed */
		memcpy(s_Response->DecryptEntireRif.raw, s_Request->DecryptEntireRif.rif.digest, sizeof(s_Request->DecryptEntireRif.rif.digest));
		memcpy(s_Response->DecryptEntireRif.raw + sizeof(s_Request->DecryptEntireRif.rif.digest), s_Request->DecryptEntireRif.rif.data, sizeof(s_Request->DecryptEntireRif.rif.data));

		memset(s_Response->DecryptEntireRif.raw +
		sizeof(s_Request->DecryptEntireRif.rif.digest) +
		sizeof(s_Request->DecryptEntireRif.rif.data),
		0,
		sizeof(s_Response->DecryptEntireRif.raw) -
		(sizeof(s_Request->DecryptEntireRif.rif.digest) +
		sizeof(s_Request->DecryptEntireRif.rif.data)));

		p_Payload->status = s_Ret;
	}

err:
	return s_Ret;
}

SblKeyRbtreeEntry* FakePkgManager::sceSblKeymgrGetKey(unsigned int p_Handle)
{
	SblKeyRbtreeEntry* s_Entry = *(SblKeyRbtreeEntry**)kdlsym(sbl_keymgr_key_rbtree);

	while (s_Entry)
	{
		if (s_Entry->handle < p_Handle)
			s_Entry = s_Entry->right;
		else if (s_Entry->handle > p_Handle)
			s_Entry = s_Entry->left;
		else if (s_Entry->handle == p_Handle)
			return s_Entry;
	}

	return nullptr;
}

int FakePkgManager::OnSceSblKeymgrInvalidateKeySxXlock(struct sx* p_Sx, int p_Opts, const char* p_File, int p_Line)
{
	//WriteLog(LL_Debug, "OnSceSblKeymgrInvalidateKeySxXlock");
	auto sceSblKeymgrSetKeyStorage = (int (*)(uint64_t key_gpu_va, unsigned int key_size, uint32_t key_id, uint32_t key_handle))kdlsym(sceSblKeymgrSetKeyStorage);
	auto sblKeymgrKeySlots = (_SblKeySlotQueue *)kdlsym(sbl_keymgr_key_slots);
	auto sblKeymgrBufVa = (uint8_t*)kdlsym(sbl_keymgr_buf_va);
	auto sblKeymgrBufGva = (uint64_t*)kdlsym(sbl_keymgr_buf_gva);
	auto _sx_xlock = (int(*)(struct sx *sx, int opts, const char *file, int line))kdlsym(_sx_xlock);

	SblKeyRbtreeEntry *keyDesc;
	SblKeySlotDesc *keySlotDesc;

	unsigned keyHandle;
	int ret, ret2;

	ret = _sx_xlock(p_Sx, p_Opts, p_File, p_Line);

	if (TAILQ_EMPTY(sblKeymgrKeySlots))
		goto done;

	TAILQ_FOREACH(keySlotDesc, sblKeymgrKeySlots, list)
	{
		keyHandle = keySlotDesc->keyHandle;
		if (keyHandle == (unsigned int) -1) {
			/* unbounded */
			WriteLog(LL_Debug, "unbounded");
			continue;
		}
		keyDesc = sceSblKeymgrGetKey(keyHandle);
		if (!keyDesc) {
			/* shouldn't happen in normal situations */
			WriteLog(LL_Debug, "shouldn't happen in normal situations");
			continue;
		}
		if (!keyDesc->occupied) {
			WriteLog(LL_Debug, "!occupied");
			continue;
		}
		if (keyDesc->desc.Pfs.obfuscatedKeyId != PFS_FAKE_OBF_KEY_ID) {
			/* not our key, just skip, so it will be handled by original code */
			WriteLog(LL_Debug, "not our key, just skip, so it will be handled by original code");
			continue;
		}
		if (keyDesc->desc.Pfs.keySize != sizeof(keyDesc->desc.Pfs.escrowedKey)) {
			/* something weird with key params, just ignore and app will just crash... */
			WriteLog(LL_Debug, "something weird with key params, just ignore and app will just crash...");
			continue;
		}
		memcpy(sblKeymgrBufVa, keyDesc->desc.Pfs.escrowedKey, keyDesc->desc.Pfs.keySize);
		//WriteLog(LL_Debug, "sblKeymgrBufGva %p %p", sblKeymgrBufGva, *sblKeymgrBufGva);
		ret2 = sceSblKeymgrSetKeyStorage(*sblKeymgrBufGva, keyDesc->desc.Pfs.keySize, keyDesc->desc.Pfs.obfuscatedKeyId, keySlotDesc->keyId);
		if (ret2) {
			WriteLog(LL_Debug, "wtf?");
			/* wtf? */
			continue;
		}
	}

done:
	/* XXX: no need to call SX unlock because we'll jump to original code which expects SX is already locked */
	return ret;
}
