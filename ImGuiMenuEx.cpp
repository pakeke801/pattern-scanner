#include "stdafx.h"
#include "dx/dx9.h"
#include "imgui/imgui.h"
#include "imgui/examples/imgui_impl_dx9.h"
#include "imgui/examples/imgui_impl_win32.h"
#include "inputhook.h"
#define MINI_CASE_SENSITIVE
#include "ini.h"
#include "ImGuiMenuEx.h"
#include "Vector.h"

#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


bool do_ini = true;
bool do_ini2 = true;

HWND window;

ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

// first, create a file instance
mINI::INIFile file("patterns.ini");
mINI::INIStructure ini;

mINI::INIFile o_file("output.ini");
mINI::INIStructure o_ini;

mINI::INIFile co_file("cobjects.ini");
mINI::INIStructure co_ini;

std::vector<offset_signature> offset_signatures;
std::list<CObject> l_object;

DWORD oLocalPlayerPtr;
DWORD oLocalPlayer;

DWORD ModuleBase;

template< typename T >
std::string hexify(T i)
{
	std::stringbuf buf;
	std::ostream os(&buf);


	os << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2)
		<< std::hex << i;

	return buf.str().c_str();
}

char* unconstchar(const char* s) {
	if (!s)
		return NULL;
	int i;
	char* res = NULL;
	res = (char*)malloc(strlen(s) + 1);
	if (!res) {
		fprintf(stderr, "Memory Allocation Failed! Exiting...\n");
		exit(EXIT_FAILURE);
	}
	else {
		for (i = 0; s[i] != '\0'; i++) {
			res[i] = s[i];
		}
		res[i] = '\0';
		return res;
	}
}

const std::vector<std::string> explode(const std::string& s, const char& c)
{
	std::string buff{ "" };
	std::vector<std::string> v;

	for (auto n : s)
	{
		if (n != c) buff += n; else
			if (n == c && buff != "") { v.push_back(buff); buff = ""; }
	}
	if (buff != "") v.push_back(buff);

	return v;
}

uint8_t* find_signature(const wchar_t* szModule, const char* szSignature) {
	auto module = GetModuleHandle(szModule);
	static auto pattern_to_byte = [](const char* pattern) {
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	};

	auto dosHeader = (PIMAGE_DOS_HEADER)module;
	auto ntHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)module + dosHeader->e_lfanew);
	auto textSection = IMAGE_FIRST_SECTION(ntHeaders);

	auto sizeOfImage = textSection->SizeOfRawData;
	auto patternBytes = pattern_to_byte(szSignature);
	auto scanBytes = reinterpret_cast<uint8_t*>(module) + textSection->VirtualAddress;

	auto s = patternBytes.size();
	auto d = patternBytes.data();

	auto mbi = MEMORY_BASIC_INFORMATION{ 0 };
	uint8_t* next_check_address = 0;

	for (auto i = 0ul; i < sizeOfImage - s; ++i) {
		bool found = true;
		for (auto j = 0ul; j < s; ++j) {
			auto current_address = scanBytes + i + j;
			if (current_address >= next_check_address) {
				if (!VirtualQuery(reinterpret_cast<void*>(current_address), &mbi, sizeof(mbi)))
					break;

				if (mbi.Protect == PAGE_NOACCESS) {
					i += ((std::uintptr_t(mbi.BaseAddress) + mbi.RegionSize) - (std::uintptr_t(scanBytes) + i));
					i--;
					found = false;
					break;
				}
				else {
					next_check_address = reinterpret_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
				}
			}

			if (scanBytes[i + j] != d[j] && d[j] != -1) {
				found = false;
				break;
			}
		}
		if (found) {
			return &scanBytes[i];
		}
	}
	return nullptr;
}

void getAddys() {
	auto base = std::uintptr_t(GetModuleHandle(nullptr));

	std::vector<offset_signature> _offset_signatures;

	for (offset_signature _o_sig : offset_signatures)
	{
		if (!_o_sig.offset)
		{
			_o_sig._offset = "Can't find offset";

			for (auto& pattern : _o_sig.sigs) {
				auto address = find_signature(nullptr, pattern.c_str());
				if (address) {
					if (_o_sig.read)
						address = *reinterpret_cast<uint8_t**>(address + (pattern.find_first_of("?") / 3));
					else if (address[0] == 0xE8)
						address = address + *reinterpret_cast<uint32_t*>(address + 1) + 5;

					if (_o_sig.sub_base)
						address -= base;

					address += _o_sig.additional;

					_o_sig.offset = reinterpret_cast<uint32_t>(address);
					_o_sig._offset = hexify <uint32_t>(_o_sig.offset);
					break;
				}
			}
			if ((_o_sig._name.compare("oLocalPlayer") == 0) && _o_sig.offset)
				oLocalPlayerPtr = _o_sig.offset;

		}
		_offset_signatures.push_back(_o_sig);
	}

	offset_signatures = _offset_signatures;
}

void getVersion(std::string address) {
	DWORD m_dwIP = std::strtoul(address.c_str(), NULL, 16);
	typedef char* (*fnGetGameVer)();
	fnGetGameVer GetGameVer = (fnGetGameVer)((DWORD)GetModuleHandleA(NULL) + m_dwIP);
	char * gamever = GetGameVer();
	std::string gameVerStr(gamever);
	o_ini["Info"]["LoL_Ver"] = gameVerStr;
}

void saveOutputIni() {
	o_ini["Info"]["Credits"] = "pakeke80 and all members who contributed to the UC LoL section.";
	for (offset_signature _o_sig : offset_signatures)
	{
		o_ini["Offsets"][_o_sig._name] = _o_sig._offset;

		if (_o_sig._name.compare("oGameVersion") == 0 && _o_sig.offset)
			getVersion(_o_sig._offset);
	}

	for (CObject obj : l_object)
	{
		o_ini["CObject"][obj.name] = obj.offset;
	}
	o_file.write(o_ini);
}

void getLocalPlayer() {
	oLocalPlayer = *(DWORD*)((DWORD)GetModuleHandleA(NULL) + oLocalPlayerPtr);
}

char* GetStr(DWORD offset) {
	if (*(int*)(offset + 0x10) > 15)
		return (char*)(*(DWORD*)offset);
	else
		return (char*)offset;
}

char* GetStr2(DWORD offset) {
	//if (*(int*)(offset + 0x10) > 15)
	return (char*)(*(DWORD*)offset);
	//else
		//return (char*)offset;
}

void getValueFromLocalPlayerOffset(std::string type, DWORD offset) {
	if (type.compare("float") == 0) {
		float val = *(float*)((DWORD)oLocalPlayer + offset);
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("In-game Value: " + std::to_string(val)).c_str());
	}
	else if (type.compare("short") == 0) {
		short val = *(short*)((DWORD)oLocalPlayer + offset);
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("In-game Value: " + std::to_string(val)).c_str());
	}
	else if (type.compare("int") == 0) {
		int val = *(int*)((DWORD)oLocalPlayer + offset);
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("In-game Value: " + std::to_string(val)).c_str());
	}
	else if (type.compare("Vector") == 0) {
		Vector val = *(Vector*)((DWORD)oLocalPlayer + offset);
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("In-game Value: X=" + std::to_string(val.X) + " Y=" + std::to_string(val.Y) + " Z=" + std::to_string(val.Z)).c_str());
	}
	else if (type.compare("DWORD") == 0) {
		DWORD val = *(DWORD*)((DWORD)oLocalPlayer + offset);
		std::string hexified = "0x0";
		hexified = hexify< DWORD >(val);
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("In-game Value: " + hexified).c_str());
	}
	else if (type.compare("bool") == 0) {
		bool val = *(bool*)((DWORD)oLocalPlayer + offset);
		if (val) {
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "In-game Value: true");
		}
		else {
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "In-game Value: false");
		}
	}
	else if (type.compare("str1") == 0) {
		auto val = GetStr((DWORD)oLocalPlayer + offset);
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("In-game Value: " + std::string(val)).c_str());
	}
	else if (type.compare("str2") == 0) {
		auto val = GetStr2((DWORD)oLocalPlayer + offset);
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("In-game Value: " + std::string(val)).c_str());
	}

}

static bool inputs_step = true;
const ImS32  s32_one = 1;

static char newInputName[128] = "oObjHealth";
static char newInputHex[128] = "0xDC4";
const char* items[] = { "float", "short", "int", "Vector", "DWORD", "bool", "str1", "str2" };
static int item_current_3 = 2; // If the selection isn't within 0..count, Combo won't display a preview

void __stdcall main_render(IDirect3DDevice9* p_device)
{
	if (GetAsyncKeyState(VK_INSERT) & 0x1) {
		DX11::InputHook::showMenu = !DX11::InputHook::showMenu;
		////MessageBoxA(0, "DoPresent. Opening Menu.", "Success", MB_ICONERROR | MB_DEFAULT_DESKTOP_ONLY);
	}

	if (GetAsyncKeyState(VK_HOME) & 0x1) {
		getAddys();
	}

	if (GetAsyncKeyState(VK_DELETE) & 0x1) {
		saveOutputIni();
	}

	//printf("zz\n");
	if (do_ini)
	{
		D3DDEVICE_CREATION_PARAMETERS parameters;
		ZeroMemory(&parameters, sizeof(parameters));
		p_device->GetCreationParameters(&parameters);
		window = parameters.hFocusWindow;

		//window = GetForegroundWindow();
		//DWORD pid;
		//if (!window || !GetWindowThreadProcessId(window, &pid) || pid != GetCurrentProcessId())
		//	return;	
		do_ini = false;
		//p_window_proc = reinterpret_cast<WNDPROC>(SetWindowLongPtr(window, GWLP_WNDPROC, LONG_PTR(wnd_proc)));
		DX11::InputHook::LoadHook(window);
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGui_ImplWin32_Init(window);
		ImGui_ImplDX9_Init(p_device);
		ImGui::StyleColorsDark();

		// now we can read the file
		file.read(ini);
		o_file.read(o_ini);
		co_file.read(co_ini);

		for (auto const& it : ini)
		{
			auto const& section = it.first;
			auto const& collection = it.second;
			//std::string _text = "[" + section + "]";
			offset_signature _o_sig;
			_o_sig._name = section;
			_o_sig._sigs = collection.get("sigs");
			_o_sig._sub_base = collection.get("sub_base");
			_o_sig._read = collection.get("read");
			_o_sig._additional = collection.get("additional");
			_o_sig._offset = "Not yet computed";

			_o_sig.sigs = explode(_o_sig._sigs, ',');
			_o_sig.sub_base = (_o_sig._sub_base.compare("true") == 0) ? true : false;
			_o_sig.read = (_o_sig._read.compare("true") == 0) ? true : false;
			_o_sig.additional = atoi(_o_sig._additional.c_str());
			_o_sig.offset = 0;

			offset_signatures.push_back(_o_sig);
		}

		for (auto const& it : co_ini)
		{
			auto const& section = it.first;
			auto const& collection = it.second;
			//std::string _text = "[" + section + "]";
			CObject obj;
			obj.name = section;
			obj.offset = collection.get("offset");
			obj.type = collection.get("type");
			l_object.push_back(obj);
		}
		ModuleBase = (DWORD)GetModuleHandleA(NULL);
		//SigScanner.GetProcess("GFXTest32.exe");
		//mod = SigScanner.GetModule("GFXTest32.exe");
	}

	if (do_ini2 && (GetAsyncKeyState(VK_END) & 0x1))
	{
		getAddys();
		if (oLocalPlayerPtr) {
			getLocalPlayer();
			do_ini2 = false;
		}
	}

	DX11::InputHook::ValidateHook(window);

	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	if (DX11::InputHook::showMenu) {
		//ImGui::ShowDemoWindow();

		ImGuiWindowFlags window_flags = 0;
		window_flags |= ImGuiWindowFlags_NoTitleBar/* | ImGuiWindowFlags_AlwaysAutoResize*/;

		ImGui::Begin("Addys", &DX11::InputHook::showMenu, window_flags);
		// Pass a pointer to our bool variable (the window will have a closing button that will clear the bool when clicked)
		ImGui::Text("Press HOME button to calculate offsets");
		ImGui::Text("Press DELETE button to save offsets to file");
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "(DO THIS ONLY AFTER LOADING SCREEN)");
		ImGui::Text("Made by pakeke80@UC");
		std::string hexifiedBase = "0x0";
		hexifiedBase = hexify< DWORD >(ModuleBase);
		ImGui::Text(("Module Base: "+ hexifiedBase).c_str());

		//std::string hexifiedMBase = "0x0";
		//hexifiedMBase = hexify< DWORD >(mod.dwBase);
		//ImGui::Text(("Mod Base: " + hexifiedMBase).c_str());

		//std::string hexifiedMSize = "0x0";
		//hexifiedMSize = hexify< DWORD >(mod.dwSize);
		//ImGui::Text(("Mod Size: " + hexifiedMSize).c_str());

		ImGui::Separator();
		for (offset_signature _o_sig : offset_signatures)
		{
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("[" + _o_sig._name + "]").c_str());
			//ImGui::Text(("Sigs: "+ _o_sig._sigs).c_str());
			//ImGui::Text(("Sub Base: " + _o_sig._sub_base).c_str());
			//ImGui::Text(("Read: " + _o_sig._read).c_str());
			//ImGui::Text(("Additional: " + _o_sig._additional).c_str());
			ImGui::Text(("Offset: " + _o_sig._offset).c_str());
			//ImGui::Text("=======================================");
			//============================
			std::string sub_base = (_o_sig.sub_base) ? "true" : "false";
			std::string read = (_o_sig.read) ? "true" : "false";
			std::string additional = std::to_string(_o_sig.additional);
			std::string offset = std::to_string(_o_sig.offset);
			//==============================
			int i = 0;
			for (auto& pattern : _o_sig.sigs)
			{
				ImGui::Text(("Sigs[" + std::to_string(i) + "]: " + pattern).c_str());
				i++;
			}
			ImGui::Text(("Sub Base: " + sub_base).c_str());
			ImGui::Text(("Read: " + read).c_str());
			ImGui::Text(("Additional: " + additional).c_str());
			//ImGui::Text(("Offset: " + offset).c_str());

			ImGui::Separator();
		}

		ImGui::End();

		//CObject
		ImGui::Begin("CObject", &DX11::InputHook::showMenu, window_flags);
		// Pass a pointer to our bool variable (the window will have a closing button that will clear the bool when clicked)
		ImGui::Text("Press END button to load LocalPlayer Data.");
		ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "(DO THIS ONLY AFTER LOADING SCREEN)");
		ImGui::Text("Made by pakeke80@UC");

		if (oLocalPlayerPtr) {
			std::string hexified = "0x0";
			hexified = hexify< DWORD >(oLocalPlayerPtr);
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("oLocalPlayerPtr: " + hexified).c_str());
		}

		if (!do_ini2) {
			std::string hexifiedZ = "0x0";
			hexifiedZ = hexify< DWORD >(oLocalPlayer);
			ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("oLocalPlayer: " + hexifiedZ).c_str());
		}
		ImGui::Separator();
		
		ImGui::InputText("Name", newInputName, IM_ARRAYSIZE(newInputName));
		ImGui::InputText("Offset", newInputHex, IM_ARRAYSIZE(newInputHex));
		ImGui::Combo("Data Type", &item_current_3, items, IM_ARRAYSIZE(items));
		if (ImGui::Button("Add Entry")) {
			CObject obj;
			obj.name = std::string(newInputName);
			obj.offset = std::string(newInputHex);
			obj.type = std::string(items[item_current_3]);

			l_object.push_back(obj);
		}
		ImGui::Separator();
		std::list<CObject> _l_object;
		for (CObject obj : l_object)
		{
			//ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), ("[" + obj.name + "]").c_str());

			DWORD offset = std::strtoul(obj.offset.c_str(), NULL, 16);
			ImGui::Text(("Type: "+obj.type).c_str());
			ImGui::InputScalar(("[" + obj.name + "]").c_str(), ImGuiDataType_S32, &offset, inputs_step ? &s32_one : NULL, NULL, "%08X", ImGuiInputTextFlags_CharsHexadecimal);

			std::string hexified2 = "0x0";
			hexified2 = hexify< DWORD >(offset);
			obj.offset = hexified2;

			//ImGui::Text(("Hex->Int: "+obj.offset).c_str());

			if (!do_ini2) {
				getValueFromLocalPlayerOffset(obj.type, offset);
			}
			
			ImGui::Separator();

			_l_object.push_back(obj);
		}
		l_object = _l_object;

		ImGui::End();
	}

	// Rendering
	ImGui::EndFrame();
	ImGui::Render();
	ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
}

auto gaks	= reinterpret_cast<void*>(&GetAsyncKeyState);
auto gks	= reinterpret_cast<void*>(&GetKeyState);
void xigncode3_un_hook()
{
	DWORD old;
	const size_t alloc_size = 100;
	const auto alloc_gaks	= malloc(alloc_size);
	const auto alloc_gks	= malloc(alloc_size);
	if (!alloc_gaks || !alloc_gks)
		return;

	memcpy(alloc_gaks,	gaks,	alloc_size);
	memcpy(alloc_gks,	gks,	alloc_size);
	VirtualProtect(gaks,	alloc_size, PAGE_EXECUTE_READWRITE, &old);
	VirtualProtect(gks,		alloc_size, PAGE_EXECUTE_READWRITE, &old);
	while (true)
	{
		if (memcmp(gaks, alloc_gaks, alloc_size) != 0 && memcmp(gks, alloc_gks, alloc_size) != 0)
		{
			memcpy(gaks,	alloc_gaks, alloc_size);
			memcpy(gks,		alloc_gks,	alloc_size);
			break;
		}
		Sleep(100);
	}
	free(alloc_gaks);
	free(alloc_gks);
}

void do_thread()
{
	printf("ini\n");
	dx9::set_frame_render(reinterpret_cast<void*>( main_render ));
	xigncode3_un_hook();
}

void open_console(const std::string title)
{
	//AllocConsole();
	//FILE* street;
	//freopen_s(&street, "CONIN$", "r", stdin);
	//freopen_s(&street, "CONOUT$", "w", stdout);
	//freopen_s(&street, "CONOUT$", "w", stderr);
	//SetConsoleTitle(title.c_str());
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		open_console("");
		CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(do_thread), nullptr, 0, nullptr);
	}
	return TRUE;
}
