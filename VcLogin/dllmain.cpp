// ============================================================================
// VcLogin v5.1 – Vietcong 1 autentizace
// Autor: Pavel Kalaš (Floxen)
// ============================================================================

#include <windows.h>
#include <detours.h>
#include <process.h>
#include <unordered_set>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>
#include <algorithm>
#include <ctime>
#include <random>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <sys/stat.h>
#include <mutex>
#include <atomic>
#include <thread>
#include <cstdarg>
using namespace std;

// ============================================================================
// Forward deklarace
// ============================================================================
struct PlayerData;
class  Cryptography;
class  IniParser;
class  PlayerManager;
class  PlayerDatabase;
class  CommandHandler;
class  PlayerConnectionWatcher;
class  MessageManager;

PlayerConnectionWatcher* g_playerConnectionWatcher = nullptr;

// ============================================================================
// Konstanty – soubory
// ============================================================================
constexpr auto KEY_FILE = "vclogin.key";
constexpr auto CONFIG_FILE = "vclogin.ini";
constexpr auto ADMIN_FILE = "admins.ini";
constexpr auto AUTO_LOGIN_FILE = "autologin.dat";
constexpr auto CONNECTIONS_FILE = "connections.txt";
std::string g_encryptionKey = "FloxenIsKing";
constexpr auto FIELD_DELIM = '§';

// Handly DLL
HMODULE g_gameDLL = nullptr;
HMODULE g_logsDLL = nullptr;

// Globální nastavení
std::string g_databasePath = "players.dat";
int         g_minPasswordLength = 4;
int         g_maxPasswordLength = 32;
int         g_maxLoginAttempts = 3;
int         g_chatCooldownSec = 2;

// Pointery na originální funkce
using OnMessage_t = int(__cdecl*)(int, int);
using OnMessageRender_t = void(__stdcall*)(int, wchar_t*, int, int, int);
using WriteBitsAligned_t = void(__cdecl*)(void*, unsigned int*, const void*, int);
using SendMessageToRemoteClient_t = void(__cdecl*)(int, void*, int, int, int);
using OnPlayerCreate_t = DWORD * (__cdecl*)(int*, int);

OnMessage_t                 OriginalOnMessage = nullptr;
OnMessageRender_t           OriginalOnMessageRender = nullptr;
WriteBitsAligned_t          WriteBitsAligned = nullptr;
SendMessageToRemoteClient_t SendMessageToRemoteClient = nullptr;
OnPlayerCreate_t OnPlayerCreate = nullptr;

using GetClientAddress_t = BOOL(__cdecl*)(void*, int, int);
GetClientAddress_t GetClientAddress = nullptr;

// Globální instance
PlayerManager* g_playerManager = nullptr;
PlayerDatabase* g_playerDatabase = nullptr;
IniParser* g_iniParser = nullptr;
CommandHandler* g_commandHandler = nullptr;
MessageManager* g_messageManager = nullptr;

// Zámky
std::mutex g_failedLoginsMutex;
std::mutex g_cooldownsMutex;
std::mutex g_msgTimeMutex;

// Mapy
std::unordered_map<std::string, int>     g_failedLoginAttemptsPerPlayer;
std::unordered_map<std::string, time_t>  g_commandCooldownTimestamps;

// ============================================================================
// Forward deklarace hooků
// ============================================================================
static int  __cdecl OnMessageHook(int playerId, int packetPtr);
static void __stdcall OnMessageRenderHook(int id, wchar_t* prefix, int msgContent, int cbfIndex, int isHost);
unsigned int SendCommand(const char* command);

// ============================================================================
// Pomocné funkce
// ============================================================================
static bool IsFunctionHooked(void* target, void* expectedHook) {
	BYTE actual[5];
	DWORD oldProtect;
	VirtualProtect(target, 5, PAGE_EXECUTE_READ, &oldProtect);
	memcpy(actual, target, 5);
	VirtualProtect(target, 5, oldProtect, &oldProtect);
	return (actual[0] == 0xE9 && *(uintptr_t*)((uintptr_t)target + 1) == (uintptr_t)expectedHook - (uintptr_t)target - 5);
}

static DWORD WINAPI HookMonitor(LPVOID) {
	while (true) {
		if (OriginalOnMessage && !IsFunctionHooked(OriginalOnMessage, (void*)OnMessageHook))
			DetourAttach(&(PVOID&)OriginalOnMessage, (PVOID)OnMessageHook);
		if (OriginalOnMessageRender && !IsFunctionHooked(OriginalOnMessageRender, (void*)OnMessageRenderHook))
			DetourAttach(&(PVOID&)OriginalOnMessageRender, (PVOID)OnMessageRenderHook);
		Sleep(1000);
	}
	return 0;
}

std::string Trim(const char* str) noexcept {
	if (!str) return {};
	std::string s(str);
	size_t start = 0;
	while (start < s.length() && isspace((unsigned char)s[start])) ++start;
	size_t end = s.length();
	while (end > start && isspace((unsigned char)s[end - 1])) --end;
	return s.substr(start, end - start);
}
std::string Trim(const std::string& str) noexcept { return Trim(str.c_str()); }

std::vector<std::string> Split(const std::string& str, char delimiter) {
	std::vector<std::string> parts;
	std::stringstream stream(str);
	std::string item;
	while (std::getline(stream, item, delimiter)) parts.push_back(item);
	return parts;
}

std::string ToLower(const std::string& str) {
	std::string lower = str;
	std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
	return lower;
}

bool FileExists(const std::string& filename) {
	DWORD attribs = GetFileAttributesA(filename.c_str());
	return (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
}

void CreateFileIfNotExists(const std::string& filename) {
	if (!FileExists(filename)) std::ofstream(filename).close();
}

// ============================================================================
// Vytvoří výchozí vclogin.ini
// ============================================================================
void CreateDefaultConfigIfMissing() {
	if (FileExists(CONFIG_FILE)) return;
	std::ofstream cfg(CONFIG_FILE);
	if (!cfg.is_open()) return;
	cfg << "; VcLogin v5.1 by Floxen\n"
		<< "; discord: swipesznx6\n"
		<< "; web: https://pavelkalas.cz\n\n"
		<< "database_file = players.db\n"
		<< "custom_message = Hello, world!\n"
		<< "min_password_length = 6\n"
		<< "max_password_length = 32\n"
		<< "max_password_tries_per_connection = 3\n"
		<< "chat_cooldown_time = 2\n"
		<< "guest_mode = 1\n"
		<< "guest_mode_join_spawn_delay = 10\n"
		<< "guest_mode_secure_account_msg_repeat_time = 5\n";
	cfg.close();
}

// ============================================================================
// Kryptografie (MD5 + XOR)
// ============================================================================
class Cryptography {
public:
	static std::string MD5(const std::string& input) {
		Cryptography ctx;
		ctx.Init();
		ctx.Update((const uint8_t*)input.c_str(), input.size());
		return ctx.Final();
	}
	static std::string XorEncryptDecrypt(const std::string& data, const std::string& key) {
		std::string out = data;
		for (size_t i = 0; i < data.size(); ++i)
			out[i] ^= key[i % key.size()];
		return out;
	}
private:
	void Init() {
		bitCount = 0; finished = false;
		state[0] = 0x67452301; state[1] = 0xefcdab89;
		state[2] = 0x98badcfe; state[3] = 0x10325476;
	}
	void Update(const uint8_t* input, size_t length) {
		size_t index = (bitCount / 8) % 64;
		bitCount += (uint64_t)length * 8;
		size_t partLen = 64 - index;
		size_t i = 0;
		if (length >= partLen) {
			memcpy(buffer + index, input, partLen);
			Transform(buffer);
			for (i = partLen; i + 63 < length; i += 64)
				Transform(input + i);
			index = 0;
		}
		memcpy(buffer + index, input + i, length - i);
	}
	std::string Final() {
		if (finished) return {};
		uint8_t bits[8];
		Encode((const uint32_t*)&bitCount, bits, 8);
		size_t index = (bitCount / 8) % 64;
		size_t padLen = (index < 56) ? (56 - index) : (120 - index);
		const uint8_t PADDING[64] = { 0x80 };
		Update(PADDING, padLen);
		Update(bits, 8);
		uint8_t digest[16];
		Encode(state, digest, 16);
		std::stringstream hexStream;
		for (int i = 0; i < 16; ++i)
			hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
		finished = true;
		return hexStream.str();
	}
	void Transform(const uint8_t block[64]) {
		uint32_t a = state[0], b = state[1], c = state[2], d = state[3], m[16];
		Decode(block, m, 64);
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF(a,b,c,d,x,s,ac) { a += F(b,c,d)+x+ac; a = ROTATE_LEFT(a,s)+b; }
#define GG(a,b,c,d,x,s,ac) { a += G(b,c,d)+x+ac; a = ROTATE_LEFT(a,s)+b; }
#define HH(a,b,c,d,x,s,ac) { a += H(b,c,d)+x+ac; a = ROTATE_LEFT(a,s)+b; }
#define II(a,b,c,d,x,s,ac) { a += I(b,c,d)+x+ac; a = ROTATE_LEFT(a,s)+b; }
		FF(a, b, c, d, m[0], 7, 0xd76aa478); FF(d, a, b, c, m[1], 12, 0xe8c7b756);
		FF(c, d, a, b, m[2], 17, 0x242070db); FF(b, c, d, a, m[3], 22, 0xc1bdceee);
		FF(a, b, c, d, m[4], 7, 0xf57c0faf); FF(d, a, b, c, m[5], 12, 0x4787c62a);
		FF(c, d, a, b, m[6], 17, 0xa8304613); FF(b, c, d, a, m[7], 22, 0xfd469501);
		FF(a, b, c, d, m[8], 7, 0x698098d8); FF(d, a, b, c, m[9], 12, 0x8b44f7af);
		FF(c, d, a, b, m[10], 17, 0xffff5bb1); FF(b, c, d, a, m[11], 22, 0x895cd7be);
		FF(a, b, c, d, m[12], 7, 0x6b901122); FF(d, a, b, c, m[13], 12, 0xfd987193);
		FF(c, d, a, b, m[14], 17, 0xa679438e); FF(b, c, d, a, m[15], 22, 0x49b40821);
		GG(a, b, c, d, m[1], 5, 0xf61e2562); GG(d, a, b, c, m[6], 9, 0xc040b340);
		GG(c, d, a, b, m[11], 14, 0x265e5a51); GG(b, c, d, a, m[0], 20, 0xe9b6c7aa);
		GG(a, b, c, d, m[5], 5, 0xd62f105d); GG(d, a, b, c, m[10], 9, 0x02441453);
		GG(c, d, a, b, m[15], 14, 0xd8a1e681); GG(b, c, d, a, m[4], 20, 0xe7d3fbc8);
		GG(a, b, c, d, m[9], 5, 0x21e1cde6); GG(d, a, b, c, m[14], 9, 0xc33707d6);
		GG(c, d, a, b, m[3], 14, 0xf4d50d87); GG(b, c, d, a, m[8], 20, 0x455a14ed);
		GG(a, b, c, d, m[13], 5, 0xa9e3e905); GG(d, a, b, c, m[2], 9, 0xfcefa3f8);
		GG(c, d, a, b, m[7], 14, 0x676f02d9); GG(b, c, d, a, m[12], 20, 0x8d2a4c8a);
		HH(a, b, c, d, m[5], 4, 0xfffa3942); HH(d, a, b, c, m[8], 11, 0x8771f681);
		HH(c, d, a, b, m[11], 16, 0x6d9d6122); HH(b, c, d, a, m[14], 23, 0xfde5380c);
		HH(a, b, c, d, m[1], 4, 0xa4beea44); HH(d, a, b, c, m[4], 11, 0x4bdecfa9);
		HH(c, d, a, b, m[7], 16, 0xf6bb4b60); HH(b, c, d, a, m[10], 23, 0xbebfbc70);
		HH(a, b, c, d, m[13], 4, 0x289b7ec6); HH(d, a, b, c, m[0], 11, 0xeaa127fa);
		HH(c, d, a, b, m[3], 16, 0xd4ef3085); HH(b, c, d, a, m[6], 23, 0x04881d05);
		HH(a, b, c, d, m[9], 4, 0xd9d4d039); HH(d, a, b, c, m[12], 11, 0xe6db99e5);
		HH(c, d, a, b, m[15], 16, 0x1fa27cf8); HH(b, c, d, a, m[2], 23, 0xc4ac5665);
		II(a, b, c, d, m[0], 6, 0xf4292244); II(d, a, b, c, m[7], 10, 0x432aff97);
		II(c, d, a, b, m[14], 15, 0xab9423a7); II(b, c, d, a, m[5], 21, 0xfc93a039);
		II(a, b, c, d, m[12], 6, 0x655b59c3); II(d, a, b, c, m[3], 10, 0x8f0ccc92);
		II(c, d, a, b, m[10], 15, 0xffeff47d); II(b, c, d, a, m[1], 21, 0x85845dd1);
		II(a, b, c, d, m[8], 6, 0x6fa87e4f); II(d, a, b, c, m[15], 10, 0xfe2ce6e0);
		II(c, d, a, b, m[6], 15, 0xa3014314); II(b, c, d, a, m[13], 21, 0x4e0811a1);
		II(a, b, c, d, m[4], 6, 0xf7537e82); II(d, a, b, c, m[11], 10, 0xbd3af235);
		II(c, d, a, b, m[2], 15, 0x2ad7d2bb); II(b, c, d, a, m[9], 21, 0xeb86d391);
		state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	}
	void Encode(const uint32_t* input, uint8_t* output, size_t length) {
		for (size_t i = 0, j = 0; j < length; i++, j += 4) {
			output[j] = (uint8_t)(input[i] & 0xff);
			output[j + 1] = (uint8_t)((input[i] >> 8) & 0xff);
			output[j + 2] = (uint8_t)((input[i] >> 16) & 0xff);
			output[j + 3] = (uint8_t)((input[i] >> 24) & 0xff);
		}
	}
	void Decode(const uint8_t* input, uint32_t* output, size_t length) {
		for (size_t i = 0, j = 0; j < length; i++, j += 4)
			output[i] = (uint32_t)input[j] | ((uint32_t)input[j + 1] << 8) |
			((uint32_t)input[j + 2] << 16) | ((uint32_t)input[j + 3] << 24);
	}
	uint32_t state[4]{};
	uint64_t bitCount{};
	uint8_t  buffer[64]{};
	bool     finished{};
};

// ============================================================================
// INI parser
// ============================================================================
class IniParser {
	std::unordered_map<std::string, std::string> data;
public:
	bool Load(const std::string& filename) {
		std::ifstream file(filename);
		if (!file) return false;
		std::string line;
		while (std::getline(file, line)) {
			line = Trim(line);
			if (line.empty() || line[0] == ';' || line[0] == '#') continue;
			size_t eqPos = line.find('=');
			if (eqPos == std::string::npos) continue;
			std::string key = Trim(line.substr(0, eqPos));
			std::string value = Trim(line.substr(eqPos + 1));
			data[key] = value;
		}
		return true;
	}
	std::string GetValue(const std::string& key) const {
		auto it = data.find(key);
		return (it != data.end()) ? it->second : "";
	}
	bool IsInt(const std::string& s) const {
		try { size_t pos; std::stoi(s, &pos); return pos == s.size(); }
		catch (...) { return false; }
	}
};

// ============================================================================
// MessageManager – všechny texty na jednom místě (anglicky, krátké)
// ============================================================================
class MessageManager {
public:
	enum MsgId {
		MSG_UNKNOWN_COMMAND,
		MSG_WELCOME_BACK,
		MSG_REG_SUCCESS,
		MSG_PW_CHANGED,
		MSG_PW_CHANGE_FAIL,
		MSG_AUTOLOGIN_ENABLED,
		MSG_AUTOLOGIN_DISABLED,
		MSG_AUTOLOGIN_IP_UPDATED,
		MSG_IP_DETECT_FAIL,
		MSG_NOT_LOGGED,
		MSG_ALREADY_LOGGED,
		MSG_DUPLICATE_NAME,
		MSG_SPECTATOR_NO_LOGIN,
		MSG_LOGIN_TIMEOUT,
		MSG_ADMIN_ONLY,
		MSG_CUSTOM_INFO,
		MSG_NO_CUSTOM_MSG,
		MSG_NOT_REGISTERED,
		MSG_ALREADY_REG,
		MSG_LOGIN_ATTEMPTS,
		MSG_TOO_MANY_ATTEMPTS,
		MSG_PW_TOO_SHORT,
		MSG_PW_TOO_LONG,
		MSG_REG_DISABLED_TEMP,
		MSG_ACCOUNT_LOCKED,
		MSG_AUTOLOGIN_WELCOME,
		MSG_IP_CHANGED,
		MSG_CHAT_COOLDOWN,
		MSG_RECOVERY_NOT_IMPL,
		MSG_ABOUT_CONSOLE,
		MSG_PROMPT_LOGIN,
		MSG_PROMPT_REGISTER,
		MSG_RECOVERY_INVALID,
		MSG_RECOVERY_SUCCESS,
		MSG_RECOVERY_CHANGE_PW,
		MSG_PW_CHANGED_NEW_CODE
	};

private:
	std::unordered_map<MsgId, std::string> messages;

public:
	MessageManager() {
		messages[MSG_UNKNOWN_COMMAND] = "Unknown command: %s";
		messages[MSG_WELCOME_BACK] = "Welcome back, %s!";
		messages[MSG_REG_SUCCESS] = "Registered! Check console for recovery code.";
		messages[MSG_PW_CHANGED] = "Password changed. Save your new recovery code in console (F12 or ;)";
		messages[MSG_PW_CHANGE_FAIL] = "Failed to change password.";
		messages[MSG_AUTOLOGIN_ENABLED] = "Auto-login enabled.";
		messages[MSG_AUTOLOGIN_DISABLED] = "Auto-login disabled.";
		messages[MSG_AUTOLOGIN_IP_UPDATED] = "Auto-login IP updated.";
		messages[MSG_IP_DETECT_FAIL] = "Could not detect your IP.";
		messages[MSG_NOT_LOGGED] = "Not logged in. Use /login <password>";
		messages[MSG_ALREADY_LOGGED] = "Already logged in.";
		messages[MSG_DUPLICATE_NAME] = "Duplicate nickname – kicked.";
		messages[MSG_SPECTATOR_NO_LOGIN] = "Spectator mode – no login needed.";
		messages[MSG_LOGIN_TIMEOUT] = "Login timeout. Rejoin and try again.";
		messages[MSG_ADMIN_ONLY] = "Admins only.";
		messages[MSG_CUSTOM_INFO] = "%s";
		messages[MSG_NO_CUSTOM_MSG] = "No custom message set by admin.";
		messages[MSG_NOT_REGISTERED] = "Not registered. Use /register <password>";
		messages[MSG_ALREADY_REG] = "Already registered. Use /login <password>";
		messages[MSG_LOGIN_ATTEMPTS] = "Wrong password. Attempt %d of %d.";
		messages[MSG_TOO_MANY_ATTEMPTS] = "Too many fails";
		messages[MSG_PW_TOO_SHORT] = "Password too short (min %d chars).";
		messages[MSG_PW_TOO_LONG] = "Password too long (max %d chars).";
		messages[MSG_REG_DISABLED_TEMP] = "Registration temporarily disabled.";
		messages[MSG_ACCOUNT_LOCKED] = "Account locked.";
		messages[MSG_AUTOLOGIN_WELCOME] = "Auto‑login: welcome back, %s!";
		messages[MSG_IP_CHANGED] = "IP changed – please log in manually.";
		messages[MSG_CHAT_COOLDOWN] = "Please wait before sending another message.";
		messages[MSG_RECOVERY_NOT_IMPL] = "Recovery not implemented yet.";
		messages[MSG_ABOUT_CONSOLE] = "VcLogin v5.1 by Floxen | Discord: swipesznx6 | https://pavelkalas.cz";
		messages[MSG_PROMPT_LOGIN] = "Press T and type /login <password>";
		messages[MSG_PROMPT_REGISTER] = "Press T and type /register <password>";
		messages[MSG_RECOVERY_INVALID] = "Invalid recovery code.";
		messages[MSG_RECOVERY_SUCCESS] = "Recovered! Change your password with /passwd <new_password>";
		messages[MSG_RECOVERY_CHANGE_PW] = "Change your password with /passwd <new_password>";
		messages[MSG_PW_CHANGED_NEW_CODE] = "New recovery code: %s";
	}

	std::string Get(MsgId id, ...) const {
		auto it = messages.find(id);
		if (it == messages.end()) return "";
		const std::string& fmt = it->second;
		va_list args;
		va_start(args, id);
		int len = _vscprintf(fmt.c_str(), args);
		if (len < 0) { va_end(args); return fmt; }
		std::vector<char> buf(len + 1);
		vsnprintf(buf.data(), buf.size(), fmt.c_str(), args);
		va_end(args);
		return std::string(buf.data());
	}

	std::string GetRaw(MsgId id) const {
		auto it = messages.find(id);
		return (it != messages.end()) ? it->second : "";
	}
};

// ============================================================================
// PlayerDatabase (stejná, jen zkrácená)
// ============================================================================
struct PlayerData {
	int id = 0;
	std::string name;
	std::string passwordHash;
	std::string regDate;
	std::string recoveryCode;
	bool locked = false;
};
struct AutoLoginRecord { std::string name; std::string ip; };

class PlayerDatabase {
	std::string m_path;
	std::vector<std::string> LoadDecrypted() const {
		std::ifstream file(m_path, std::ios::binary);
		if (!file) return {};
		std::stringstream buffer; buffer << file.rdbuf();
		std::string enc = buffer.str();
		if (enc.empty()) return {};
		std::string dec = Cryptography::XorEncryptDecrypt(enc, g_encryptionKey);
		std::vector<std::string> lines;
		std::stringstream ss(dec); std::string line;
		while (std::getline(ss, line)) lines.push_back(line);
		return lines;
	}
	void SaveEncrypted(const std::vector<std::string>& lines) const {
		std::stringstream plain;
		for (const auto& l : lines) plain << l << "\n";
		std::string enc = Cryptography::XorEncryptDecrypt(plain.str(), g_encryptionKey);
		std::ofstream file(m_path, std::ios::binary | std::ios::trunc);
		file.write(enc.data(), enc.size());
	}
	PlayerData ParseLine(const std::string& line) const {
		auto parts = Split(line, FIELD_DELIM);
		if (parts.size() < 5) throw std::runtime_error("bad record");
		PlayerData p;
		p.id = std::stoi(parts[0]);
		p.name = parts[1];
		p.passwordHash = parts[2];
		p.regDate = parts[3];
		p.recoveryCode = parts[4];
		p.locked = (line[0] == '#');
		return p;
	}
	static bool IsValidIp4(const std::string& ip) {
		std::regex pattern(R"(^(\d{1,3}\.){3}\d{1,3}$)");
		if (!std::regex_match(ip, pattern)) return false;
		std::stringstream ss(ip); std::string seg; int cnt = 0;
		while (std::getline(ss, seg, '.')) {
			int v = std::stoi(seg);
			if (v < 0 || v>255) return false;
			cnt++;
		}
		return cnt == 4;
	}
	std::vector<AutoLoginRecord> LoadAutoLogin() const {
		std::vector<AutoLoginRecord> recs;
		std::ifstream file(AUTO_LOGIN_FILE);
		std::string line, delim(1, FIELD_DELIM);
		while (std::getline(file, line)) {
			size_t pos = line.find(delim);
			if (pos != std::string::npos) {
				AutoLoginRecord r{ line.substr(0,pos), line.substr(pos + 1) };
				if (IsValidIp4(r.ip)) recs.push_back(r);
			}
		}
		return recs;
	}
	void SaveAutoLogin(const std::vector<AutoLoginRecord>& recs) const {
		std::ofstream file(AUTO_LOGIN_FILE, std::ios::trunc);
		std::string delim(1, FIELD_DELIM);
		for (const auto& r : recs) file << r.name << delim << r.ip << "\n";
	}
public:
	void SetPath(const std::string& path) { m_path = path; }
	void EnsureExists() {
		if (!FileExists(m_path)) SaveEncrypted({});
	}
	bool UpdateRecoveryCode(const std::string& name, const std::string& newCode) {
		auto lines = LoadDecrypted();
		bool updated = false;
		for (auto& l : lines) {
			bool locked = (!l.empty() && l[0] == '#');
			std::string workLine = locked ? l.substr(1) : l;
			try {
				auto p = ParseLine(workLine);
				if (ToLower(p.name) == ToLower(name)) {
					auto parts = Split(workLine, FIELD_DELIM);
					if (parts.size() < 5) continue;
					parts[4] = newCode;
					std::string d(1, FIELD_DELIM);
					workLine = parts[0] + d + parts[1] + d + parts[2] + d + parts[3] + d + parts[4];
					l = locked ? ("#" + workLine) : workLine;
					updated = true;
					break;
				}
			}
			catch (...) {}
		}
		if (updated) SaveEncrypted(lines);
		return updated;
	}
	bool Exists(const std::string& name) const {
		auto lines = LoadDecrypted();
		for (const auto& l : lines) {
			try { if (ToLower(ParseLine(l).name) == ToLower(name)) return true; }
			catch (...) {}
		}
		return false;
	}
	bool IsLocked(const std::string& name) const {
		auto lines = LoadDecrypted();
		for (const auto& l : lines) {
			try { auto p = ParseLine(l); if (ToLower(p.name) == ToLower(name) && l[0] == '#') return true; }
			catch (...) {}
		}
		return false;
	}
	bool VerifyPassword(const std::string& name, const std::string& hash) const {
		auto lines = LoadDecrypted();
		for (const auto& l : lines) {
			try { auto p = ParseLine(l); if (ToLower(p.name) == ToLower(name) && p.passwordHash == hash) return true; }
			catch (...) {}
		}
		return false;
	}
	bool ChangePassword(const std::string& name, const std::string& newPw) {
		auto lines = LoadDecrypted();
		bool updated = false;
		for (auto& l : lines) {
			try {
				auto p = ParseLine(l);
				if (ToLower(p.name) == ToLower(name)) {
					auto parts = Split(l, FIELD_DELIM);
					parts[2] = Cryptography::MD5(newPw);
					std::string delim(1, FIELD_DELIM);
					l = parts[0] + delim + parts[1] + delim + parts[2] + delim + parts[3] + delim + parts[4];
					updated = true;
					break;
				}
			}
			catch (...) {}
		}
		if (updated) SaveEncrypted(lines);
		return updated;
	}
	bool ResetPasswordAndRecovery(const std::string& name, const std::string& newPassword, const std::string& newRecoveryCode) {
		auto lines = LoadDecrypted();
		bool updated = false;
		for (auto& l : lines) {
			bool wasLocked = false;
			if (!l.empty() && l[0] == '#') {
				l = l.substr(1);
				wasLocked = true;
			}
			try {
				auto p = ParseLine(l);
				if (ToLower(p.name) == ToLower(name)) {
					auto parts = Split(l, FIELD_DELIM);
					if (parts.size() < 5) continue;
					parts[2] = Cryptography::MD5(newPassword);
					parts[4] = newRecoveryCode;
					std::string d(1, FIELD_DELIM);
					l = parts[0] + d + parts[1] + d + parts[2] + d + parts[3] + d + parts[4];
					updated = true;
					break;
				}
			}
			catch (...) {}
			if (wasLocked && !updated) l = "#" + l;
		}
		if (updated) SaveEncrypted(lines);
		return updated;
	}
	void AddPlayer(const std::string& name, const std::string& pw) {
		if (Exists(name)) return;
		auto lines = LoadDecrypted();
		time_t now = time(nullptr);
		tm tmInfo{}; localtime_s(&tmInfo, &now);
		char dateBuf[20]; strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d %H:%M:%S", &tmInfo);
		std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<> dis(100000, 999999);
		std::string recovery = std::to_string(dis(gen));
		int id = (int)lines.size() + 1;
		std::string d(1, FIELD_DELIM);
		lines.push_back(std::to_string(id) + d + name + d + Cryptography::MD5(pw) + d + dateBuf + d + recovery);
		SaveEncrypted(lines);
	}
	bool RemovePlayer(const std::string& name) {
		auto lines = LoadDecrypted();
		bool removed = false;
		lines.erase(std::remove_if(lines.begin(), lines.end(), [&](const std::string& l) {
			try { if (ToLower(ParseLine(l).name) == ToLower(name)) { removed = true; return true; } }
			catch (...) {}
			return false;
			}), lines.end());
		if (removed) { SaveEncrypted(lines); RemoveAutoLogin(name); }
		return removed;
	}
	std::string GetRecoveryCode(const std::string& name) const {
		auto lines = LoadDecrypted();
		for (const auto& l : lines) {
			try { auto p = ParseLine(l); if (ToLower(p.name) == ToLower(name)) return p.recoveryCode; }
			catch (...) {}
		}
		return {};
	}
	std::string GetIpByPlayerName(const std::string& name) const {
		auto recs = LoadAutoLogin();
		for (const auto& r : recs) if (ToLower(r.name) == ToLower(name)) return r.ip;
		return {};
	}
	void AddAutoLogin(const std::string& name, const std::string& ip) {
		auto recs = LoadAutoLogin();
		bool found = false;
		for (auto& r : recs) if (ToLower(r.name) == ToLower(name)) { r.ip = ip; found = true; break; }
		if (!found) recs.push_back({ name, ip });
		SaveAutoLogin(recs);
	}
	void RemoveAutoLogin(const std::string& name) {
		auto recs = LoadAutoLogin();
		recs.erase(std::remove_if(recs.begin(), recs.end(), [&](const AutoLoginRecord& r) {
			return ToLower(r.name) == ToLower(name);
			}), recs.end());
		SaveAutoLogin(recs);
	}
	std::string GetConnectionString(const std::string& name) const {
		std::ifstream file(CONNECTIONS_FILE);
		std::vector<std::string> lines; std::string line;
		while (std::getline(file, line)) lines.push_back(line);
		for (auto it = lines.rbegin(); it != lines.rend(); ++it)
			if (it->find(name) != std::string::npos) return *it;
		return {};
	}
};

// ============================================================================
// Síťové funkce (odesílání zpráv)
// ============================================================================
void SendMessageToPlayer(int targetId, const char* text, int fromId) {
	if (!WriteBitsAligned || !SendMessageToRemoteClient) return;
	uint8_t packet[1024] = {};
	packet[0] = 35;
	unsigned int bitOffset = 8;
	WriteBitsAligned(packet, &bitOffset, &fromId, 13);
	uint8_t flag = 0;
	WriteBitsAligned(packet, &bitOffset, &flag, 1);
	size_t len = strlen(text);
	for (size_t i = 0; i <= len; ++i)
		WriteBitsAligned(packet, &bitOffset, &text[i], 7);
	int size = (bitOffset & 7) ? (bitOffset >> 3) + 1 : (bitOffset >> 3);
	SendMessageToRemoteClient(targetId, packet, size, 2, 0);
}

void SendConsoleMessageToPlayer(int targetId, const char* text) {
	if (!WriteBitsAligned || !SendMessageToRemoteClient) return;
	uint8_t packet[1024] = {};
	unsigned int bitOffset = 0;
	size_t msgLen = strlen(text);
	uint8_t packetId = 87, msgType = 23, length = (uint8_t)((msgLen < 127) ? msgLen : 127);
	WriteBitsAligned(packet, &bitOffset, &packetId, 8);
	WriteBitsAligned(packet, &bitOffset, &msgType, 8);
	WriteBitsAligned(packet, &bitOffset, &length, 8);
	for (uint8_t i = 0; i < length; ++i)
		WriteBitsAligned(packet, &bitOffset, (uint8_t*)&text[i], 8);
	int size = (bitOffset & 7) ? (bitOffset >> 3) + 1 : (bitOffset >> 3);
	SendMessageToRemoteClient(targetId, packet, size, 2, 0);
}

unsigned int SendCommand(const char* command) {
	char* cmdBuf = (char*)((uintptr_t)g_logsDLL + 0x36D5E4);
	int* pLenA = (int*)((uintptr_t)g_logsDLL + 0x36CA74);
	int* pLenB = (int*)((uintptr_t)g_logsDLL + 0x36D040);
	int* pExec = (int*)((uintptr_t)g_logsDLL + 0x36C738);
	int len = (int)strlen(command) + 1;
	int copyLen = min(len, 250);
	memcpy(cmdBuf, command, copyLen);
	*pLenA = copyLen;
	*pLenB = copyLen;
	*pExec = 1;
	return copyLen;
}

// ============================================================================
// PlayerManager – přístup do paměti hry
// ============================================================================
class PlayerManager {
	std::unordered_set<int> playersFromRecovery;

	bool IsPointerValid(void* ptr, size_t size = sizeof(void*)) const noexcept {
		return ptr && !IsBadReadPtr(ptr, (UINT_PTR)size);
	}
	uintptr_t* GetPlayerList() const noexcept {
		return (uintptr_t*)((uintptr_t)g_gameDLL + 0x7AE9C8);
	}
	int* GetPlayerCount() const noexcept {
		return (int*)((uintptr_t)g_gameDLL + 0x80C770);
	}
public:
	void KickPlayer(int id) {
		char packetData[2];
		packetData[0] = 77;
		packetData[1] = 8;
		SendConsoleMessageToPlayer(id, "Server closed connection.");
		SendMessageToRemoteClient(id, packetData, 2u, 1, 0.0);
	}
	bool IsOnline(int id) const {
		int* cnt = GetPlayerCount(); uintptr_t* list = GetPlayerList();
		if (!IsPointerValid(cnt) || !IsPointerValid(list)) return false;
		for (int i = 0; i < *cnt; ++i) {
			int* pid = (int*)list[i];
			if (IsPointerValid(pid) && *pid == id) return true;
		}
		return false;
	}
	bool IsLogged(int id) const {
		int* cnt = GetPlayerCount(); uintptr_t* list = GetPlayerList();
		if (!IsPointerValid(cnt) || !IsPointerValid(list)) return false;
		for (int i = 0; i < *cnt; ++i) {
			uintptr_t base = list[i];
			int* pid = (int*)base;
			int* block = (int*)(base + 0xC);
			if (IsPointerValid(pid) && *pid == id && IsPointerValid(block)) return *block > 0;
		}
		return false;
	}
	std::string GetPlayerName(int id) const {
		int* cnt = GetPlayerCount(); uintptr_t* list = GetPlayerList();
		if (!IsPointerValid(cnt) || !IsPointerValid(list)) return {};
		for (int i = 0; i < *cnt; ++i) {
			uintptr_t base = list[i];
			int* pid = (int*)base;
			char* name = (char*)(base + 0x28);
			if (IsPointerValid(pid) && *pid == id && IsPointerValid(name, 1))
				return std::string(name, strnlen(name, 32));
		}
		return {};
	}
	void AllowPlayer(int id) {
		int* cnt = GetPlayerCount(); uintptr_t* list = GetPlayerList();
		if (!IsPointerValid(cnt) || !IsPointerValid(list)) return;
		for (int i = 0; i < *cnt; ++i) {
			uintptr_t base = list[i];
			int* pid = (int*)base;
			int* block = (int*)(base + 0xC);
			if (IsPointerValid(pid) && *pid == id && IsPointerValid(block)) { *block = 19; break; }
		}
	}
	bool IsSpectator(int id) const {
		int* cnt = GetPlayerCount(); uintptr_t* list = GetPlayerList();
		if (!IsPointerValid(cnt) || !IsPointerValid(list)) return false;
		for (int i = 0; i < *cnt; ++i) {
			int* pid = (int*)list[i];
			int* mode = (int*)(list[i] + 0x1C);
			if (IsPointerValid(pid) && *pid == id && IsPointerValid(mode)) return *mode == 0;
		}
		return false;
	}
	bool IsDuplicateName(const std::string& name) const {
		int* cnt = GetPlayerCount(); uintptr_t* list = GetPlayerList();
		if (!IsPointerValid(cnt) || !IsPointerValid(list)) return false;
		int found = 0;
		for (int i = 0; i < *cnt; ++i) {
			char* pname = (char*)(list[i] + 0x28);
			if (IsPointerValid(pname, 1) && name == pname) found++;
		}
		return found > 1;
	}
	void KickAllNotLogged() {
		int* cnt = GetPlayerCount(); uintptr_t* list = GetPlayerList();
		if (!IsPointerValid(cnt) || !IsPointerValid(list)) return;
		for (int i = 0; i < *cnt; ++i) {
			int* block = (int*)(list[i] + 0xC);
			int* pid = (int*)list[i];
			if (IsPointerValid(block) && IsPointerValid(pid) && *block == 0) {
				KickPlayer(*pid);
			}
		}
	}
	bool IsAdmin(const std::string& name) const {
		CreateFileIfNotExists(ADMIN_FILE);
		std::ifstream f(ADMIN_FILE); std::string line;
		while (std::getline(f, line)) if (line == name) return true;
		return false;
	}
	std::string ExtractIpFromLine(const std::string& line) const {
		std::regex ipPat(R"((\d{1,3}\.){3}\d{1,3})");
		std::smatch m;
		if (std::regex_search(line, m, ipPat)) return m.str();
		return {};
	}
};

// ============================================================================
// CommandHandler – zpracování příkazů
// ============================================================================
class CommandHandler {
	PlayerManager* pm;
	PlayerDatabase* pdb;
	IniParser* ini;
	MessageManager* msg;
	int minPwLen, maxPwLen, maxAttempts, chatCooldown;
	std::unordered_map<int, std::chrono::steady_clock::time_point> lastMsgTime;

	using MsgId = MessageManager::MsgId;

public:
	CommandHandler(PlayerManager* p, PlayerDatabase* d, IniParser* i, MessageManager* m)
		: pm(p), pdb(d), ini(i), msg(m), minPwLen(6), maxPwLen(32), maxAttempts(3), chatCooldown(2) {
	}
	void SetMinPasswordLength(int v) { minPwLen = v; }
	void SetMaxPasswordLength(int v) { maxPwLen = v; }
	void SetMaxLoginAttempts(int v) { maxAttempts = v; }
	void SetChatCooldown(int v) { chatCooldown = v; }

	bool ProcessCommand(int playerId, const std::string& cmd) {
		if (cmd.empty() || cmd[0] != '/') return false;
		std::string pname = pm->GetPlayerName(playerId);
		if (pm->IsDuplicateName(pname)) {
			SendMessageToPlayer(playerId, msg->GetRaw(MessageManager::MSG_DUPLICATE_NAME).c_str(), 1);
			return true;
		}
		std::string prefix = cmd.substr(0, cmd.find(' '));
		if (prefix == "/about")     return About(playerId);
		if (prefix == "/help")      return Help(playerId);
		if (prefix == "/info")      return Info(playerId);
		if (prefix == "/passwd")    return ChangePw(playerId, cmd, pname);
		if (prefix == "/autologin") return AutoLogin(playerId, pname);
		if (prefix == "/login")     return Login(playerId, cmd, pname);
		if (prefix == "/register")  return Register(playerId, cmd, pname);
		if (prefix == "/recovery")  return Recovery(playerId, cmd);
		SendMessageToPlayer(playerId, msg->Get(MessageManager::MSG_UNKNOWN_COMMAND, cmd.c_str()).c_str(), 2);
		return true;
	}

	bool CheckChatCooldown(int pid) {
		if (pid > 2 && chatCooldown > 0) {
			auto now = std::chrono::steady_clock::now();
			auto it = lastMsgTime.find(pid);
			if (it != lastMsgTime.end()) {
				if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() < chatCooldown) {
					SendMessageToPlayer(pid, msg->GetRaw(MessageManager::MSG_CHAT_COOLDOWN).c_str(), 2);
					return false;
				}
			}
			lastMsgTime[pid] = now;
		}
		return true;
	}

private:
	std::string ExtractArg(const std::string& cmd, const std::string& prefix) {
		if (cmd.compare(0, prefix.size(), prefix) == 0) return Trim(cmd.substr(prefix.size()));
		return {};
	}

	bool About(int id) {
		SendConsoleMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_ABOUT_CONSOLE).c_str());
		SendMessageToPlayer(id, "Info printed to console.", 2);
		return true;
	}
	bool Help(int id) {
		SendMessageToPlayer(id, "Info printed to console.", 2);
		SendConsoleMessageToPlayer(id, "");
		SendConsoleMessageToPlayer(id, "> Commands:");
		SendConsoleMessageToPlayer(id, "");
		SendConsoleMessageToPlayer(id, "/login [password] - Log you to server as user");
		SendConsoleMessageToPlayer(id, "/register [password] - Register you as new user to server");
		SendConsoleMessageToPlayer(id, "/passwd [new password] - Changes a password to your account");
		SendConsoleMessageToPlayer(id, "/autologin - Use this when you don't want use your password");
		SendConsoleMessageToPlayer(id, "/info - Shows user's defined string");
		SendConsoleMessageToPlayer(id, "/about - Shows info about this software");
		SendConsoleMessageToPlayer(id, "");
		return true;
	}
	bool Info(int id) {
		std::string custom = Trim(ini->GetValue("custom_message"));
		if (custom.empty()) SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_NO_CUSTOM_MSG).c_str(), 2);
		else SendMessageToPlayer(id, msg->Get(MessageManager::MSG_CUSTOM_INFO, custom.c_str()).c_str(), 1);
		return true;
	}
	bool ChangePw(int id, const std::string& cmd, const std::string& pname) {
		if (!pm->IsLogged(id)) {
			SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_NOT_LOGGED).c_str(), 1);
			return true;
		}
		std::string pw = ExtractArg(cmd, "/passwd ");
		if (pw.empty()) {
			SendMessageToPlayer(id, "Usage: /passwd <new_password>", 1);
			return true;
		}
		if ((int)pw.length() < minPwLen) {
			SendMessageToPlayer(id, msg->Get(MessageManager::MSG_PW_TOO_SHORT, minPwLen).c_str(), 1);
			return true;
		}
		if ((int)pw.length() > maxPwLen) {
			SendMessageToPlayer(id, msg->Get(MessageManager::MSG_PW_TOO_LONG, maxPwLen).c_str(), 1);
			return true;
		}
		if (pdb->ChangePassword(pname, pw)) {
			SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_PW_CHANGED).c_str(), 1);

			// Pokaždé při změně hesla vygenerovat nový recovery kód
			std::random_device rd;
			std::mt19937 gen(rd());
			std::uniform_int_distribution<> dis(100000, 999999);
			std::string newCode = std::to_string(dis(gen));

			pdb->UpdateRecoveryCode(pname, newCode);

			SendConsoleMessageToPlayer(id, msg->Get(MessageManager::MSG_PW_CHANGED_NEW_CODE, newCode.c_str()).c_str());
		}
		else {
			SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_PW_CHANGE_FAIL).c_str(), 1);
		}
		return true;
	}
	bool AutoLogin(int id, const std::string& pname) {
		if (!pm->IsLogged(id)) { SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_NOT_LOGGED).c_str(), 1); return true; }
		std::string oldIp = pdb->GetIpByPlayerName(pname);
		if (!oldIp.empty()) {
			pdb->RemoveAutoLogin(pname);
			SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_AUTOLOGIN_DISABLED).c_str(), 1);
		}
		else {
			std::string conn = pdb->GetConnectionString(pname);
			std::string ip = pm->ExtractIpFromLine(conn);
			if (!ip.empty()) {
				pdb->AddAutoLogin(pname, ip);
				SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_AUTOLOGIN_ENABLED).c_str(), 1);
			}
			else {
				SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_IP_DETECT_FAIL).c_str(), 2);
			}
		}
		return true;
	}
	bool Login(int id, const std::string& cmd, const std::string& pname) {
		if (pdb->IsLocked(pname)) { SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_ACCOUNT_LOCKED).c_str(), 1); return true; }
		if (pm->IsLogged(id)) { SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_ALREADY_LOGGED).c_str(), 1); return true; }
		std::string pw = ExtractArg(cmd, "/login ");
		if (pw.empty()) { SendMessageToPlayer(id, "Usage: /login <password>", 1); return true; }
		if (!pdb->Exists(pname)) { SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_NOT_REGISTERED).c_str(), 1); return true; }
		std::string hash = Cryptography::MD5(pw);
		if (pdb->VerifyPassword(pname, hash)) {
			pm->AllowPlayer(id);
			{
				std::lock_guard<std::mutex> lock(g_failedLoginsMutex);
				g_failedLoginAttemptsPerPlayer.erase(pname);
			}
			SendMessageToPlayer(id, msg->Get(MessageManager::MSG_WELCOME_BACK, pname.c_str()).c_str(), 1);
			std::string oldIp = pdb->GetIpByPlayerName(pname);
			if (!oldIp.empty()) {
				std::string conn = pdb->GetConnectionString(pname);
				std::string ip = pm->ExtractIpFromLine(conn);
				if (!ip.empty()) {
					pdb->AddAutoLogin(pname, ip);
					SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_AUTOLOGIN_IP_UPDATED).c_str(), 1);
				}
			}
		}
		else {
			std::lock_guard<std::mutex> lock(g_failedLoginsMutex);
			int attempts = ++g_failedLoginAttemptsPerPlayer[pname];
			if (attempts >= maxAttempts) {
				SendMessageToPlayer(id, msg->Get(MessageManager::MSG_TOO_MANY_ATTEMPTS).c_str(), 1);
				pm->KickPlayer(id);
			}
			else {
				SendMessageToPlayer(id, msg->Get(MessageManager::MSG_LOGIN_ATTEMPTS, attempts, maxAttempts).c_str(), 2);
			}
		}
		return true;
	}
	bool Register(int id, const std::string& cmd, const std::string& pname) {
		if (pm->IsLogged(id)) { SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_ALREADY_LOGGED).c_str(), 1); return true; }
		{
			std::lock_guard<std::mutex> lock(g_cooldownsMutex);
			time_t now = time(nullptr);
			if (g_commandCooldownTimestamps.count("register") && now < g_commandCooldownTimestamps["register"]) {
				SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_REG_DISABLED_TEMP).c_str(), 1);
				return true;
			}
		}
		std::string pw = ExtractArg(cmd, "/register ");
		if (pw.empty()) { SendMessageToPlayer(id, "Usage: /register <password>", 1); return true; }
		if (pdb->Exists(pname)) { SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_ALREADY_REG).c_str(), 1); return true; }
		if ((int)pw.length() < minPwLen) { SendMessageToPlayer(id, msg->Get(MessageManager::MSG_PW_TOO_SHORT, minPwLen).c_str(), 1); return true; }
		if ((int)pw.length() > maxPwLen) { SendMessageToPlayer(id, msg->Get(MessageManager::MSG_PW_TOO_LONG, maxPwLen).c_str(), 1); return true; }
		pdb->AddPlayer(pname, pw);
		pm->AllowPlayer(id);
		SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_REG_SUCCESS).c_str(), 1);
		int pid = id;
		std::string pn = pname;
		// Zachycení this a místních proměnných
		std::thread([this, pid, pn]() {
			SendMessageToPlayer(pid, "Use /autologin to enable auto-login", 2);
			std::string code = this->pdb->GetRecoveryCode(pn);
			SendConsoleMessageToPlayer(pid, ("Recovery code: " + code).c_str());
			SendConsoleMessageToPlayer(pid, "Save this in case you forget your password.");
			}).detach();
		return true;
	}
	bool Recovery(int id, const std::string& cmd) {
		std::string pname = pm->GetPlayerName(id);

		if (pm->IsLogged(id)) {
			return true;
		}

		if (!pdb->Exists(pname)) {
			SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_NOT_REGISTERED).c_str(), 1);
			return true;
		}

		std::string code = ExtractArg(cmd, "/recovery ");
		if (code.empty()) {
			SendMessageToPlayer(id, "Usage: /recovery <recovery_code>", 1);
			return true;
		}

		if (code != pdb->GetRecoveryCode(pname)) {
			SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_RECOVERY_INVALID).c_str(), 1);
			return true;
		}

		pm->AllowPlayer(id);

		SendMessageToPlayer(id, msg->GetRaw(MessageManager::MSG_RECOVERY_SUCCESS).c_str(), 1);

		return true;
	}
};

// ============================================================================
// PlayerConnectionWatcher – sledování nových hráčů
// ============================================================================
class PlayerConnectionWatcher {
	PlayerManager* pm;
	PlayerDatabase* pdb;
	MessageManager* msg;
	std::unordered_set<int> knownAIDs, processedAIDs;
public:
	PlayerConnectionWatcher(PlayerManager* p, PlayerDatabase* d, MessageManager* m) : pm(p), pdb(d), msg(m) {}
	void Start() {
		while (true) {
			ScanPlayers();
			Sleep(50);
		}
	}
	bool IsProcessedAID(int id) {
		int aid = GetPlayerAidById(id);
		return processedAIDs.find(aid) != processedAIDs.end();
	}
	void OnNewPlayer(const std::string& pname, const std::string& ip, int pid) {
		if (pm->IsSpectator(pid) && pname.find("Spectator(") != std::string::npos) {
			SendMessageToPlayer(pid, msg->GetRaw(MessageManager::MSG_SPECTATOR_NO_LOGIN).c_str(), 1);
			pm->AllowPlayer(pid);
			return;
		}
		if (pm->IsDuplicateName(pname)) {
			SendMessageToPlayer(pid, msg->GetRaw(MessageManager::MSG_DUPLICATE_NAME).c_str(), 1);
			pm->KickPlayer(pid);
			return;
		}
		std::string oldIp = pdb->GetIpByPlayerName(pname);
		if (!oldIp.empty()) {
			if (ip == oldIp) {
				SendMessageToPlayer(pid, msg->Get(MessageManager::MSG_AUTOLOGIN_WELCOME, pname.c_str()).c_str(), 1);
				pm->AllowPlayer(pid);
				return;
			}
			else {
				SendMessageToPlayer(pid, msg->GetRaw(MessageManager::MSG_IP_CHANGED).c_str(), 1);
			}
		}
		if (pm->IsOnline(pid)) {
			int plid = pid;
			PlayerManager* ppm = pm;
			PlayerDatabase* ppdb = pdb;
			MessageManager* pmsg = msg;
			std::thread([plid, ppm, ppdb, pmsg]() {
				std::string name = ppm->GetPlayerName(plid);
				bool registered = ppdb->Exists(name);
				for (int i = 0; i < 10; ++i) {
					if (ppm->IsLogged(plid) || !ppm->IsOnline(plid)) return;
					if (registered)
						SendMessageToPlayer(plid, pmsg->GetRaw(MessageManager::MSG_PROMPT_LOGIN).c_str(), plid);
					else
						SendMessageToPlayer(plid, pmsg->GetRaw(MessageManager::MSG_PROMPT_REGISTER).c_str(), plid);
					Sleep(10000);
				}
				if (!ppm->IsLogged(plid) && ppm->IsOnline(plid)) {
					SendMessageToPlayer(plid, pmsg->GetRaw(MessageManager::MSG_LOGIN_TIMEOUT).c_str(), 1);
					ppm->KickPlayer(plid);
				}
				}).detach();
		}
	}
private:
	int GetPlayerAidById(int targetId)
	{
		int* playerCount = (int*)((uintptr_t)g_gameDLL + 0x7BF210);

		if (!playerCount || *playerCount <= 0)
			return 0;

		float* unitDataPtr = (float*)((uintptr_t)g_gameDLL + 0x7BF244);

		if (!unitDataPtr)
			return 0;

		for (int i = 0; i < *playerCount; ++i)
		{
			int aid = *(((DWORD*)unitDataPtr) - 11);
			int id = *(((DWORD*)unitDataPtr) - 10);

			if (id == targetId)
				return aid;

			unitDataPtr += 16;
		}

		return 0;
	}
	void ScanPlayers() {
		int* playerCount = (int*)((uintptr_t)g_gameDLL + 0x7BF210);
		if (!playerCount || *playerCount <= 0) {
			knownAIDs.clear(); processedAIDs.clear();
			return;
		}
		float* unitDataPtr = (float*)((uintptr_t)g_gameDLL + 0x7BF244);
		if (!unitDataPtr) return;
		typedef int(__cdecl* GetNameFunc_t)(int);
		GetNameFunc_t GetNameFunc = (GetNameFunc_t)((uintptr_t)g_gameDLL + 0x14B590);
		std::unordered_set<int> currentAIDs;
		for (int i = 0; i < *playerCount; ++i) {
			int id = *(((DWORD*)unitDataPtr) - 10);
			int aid = *(((DWORD*)unitDataPtr) - 11);
			currentAIDs.insert(aid);
			if (knownAIDs.find(aid) == knownAIDs.end()) {
				knownAIDs.insert(aid);
				int nameAddr = GetNameFunc(id);
				const char* name = (nameAddr) ? (const char*)(nameAddr + 40) : nullptr;
				if (!name || name[0] == 0) {
					int pid = id;
					std::thread([pid]() {
						SendConsoleMessageToPlayer(pid, "");
						Sleep(50);
						SendConsoleMessageToPlayer(pid, "> VcLogin v5.1 Community edition active - https://PavelKalas.cz (Floxen)");
						Sleep(50);
						SendConsoleMessageToPlayer(pid, "");
						}).detach();
				}
			}
			else if (processedAIDs.find(aid) == processedAIDs.end()) {
				int nameAddr = GetNameFunc(id);
				const char* name = (nameAddr) ? (const char*)(nameAddr + 40) : nullptr;
				if (name && name[0] != 0) {
					processedAIDs.insert(aid);
				}
			}
			unitDataPtr += 16;
		}
		for (auto it = knownAIDs.begin(); it != knownAIDs.end(); ) {
			if (currentAIDs.find(*it) == currentAIDs.end()) {
				processedAIDs.erase(*it);
				it = knownAIDs.erase(it);
			}
			else ++it;
		}
	}
};

// ============================================================================
// ReadBitsAligned (pomocná)
// ============================================================================
DWORD* __cdecl ReadBitsAligned(int baseAddr, DWORD* bitOffset, BYTE* outBuf, unsigned int bitsToRead) {
	unsigned int remaining = bitsToRead;
	BYTE* curByte = (BYTE*)(baseAddr + (*bitOffset >> 3));
	unsigned int bitsLeftInByte = 8 - (*bitOffset & 7);
	unsigned int bitsLeft = bitsToRead;
	if (!bitsToRead) return bitOffset;
	do {
		unsigned int toProcess = min(bitsLeft, 8u);
		bitsLeft -= toProcess;
		char outByte = 0;
		int outBitIndex = 0;
		if (toProcess) {
			do {
				unsigned int fromCurrent = min(bitsLeftInByte, toProcess);
				char extracted = ((0xFF >> (8 - fromCurrent)) & (*curByte >> (8 - bitsLeftInByte))) << outBitIndex;
				outBitIndex += fromCurrent;
				bitsLeftInByte -= fromCurrent;
				outByte |= extracted;
				if (!bitsLeftInByte) { ++curByte; bitsLeftInByte = 8; }
				toProcess -= fromCurrent;
			} while (toProcess);
		}
		*outBuf++ = outByte;
	} while (bitsLeft);
	*bitOffset += remaining;
	return bitOffset;
}

// ============================================================================
// Hook funkce
// ============================================================================
static int __cdecl OnMessageHook(int playerId, int packetPtr) {
	if (!g_commandHandler) return OriginalOnMessage(playerId, packetPtr);
	DWORD bitPos = 8;
	DWORD msgLen = 0;
	char ch = 0;
	char message[128] = { 0 };
	int idx = 0;
	ReadBitsAligned(packetPtr, &bitPos, (BYTE*)&msgLen, 1);
	do {
		ch = 0;
		ReadBitsAligned(packetPtr, &bitPos, (BYTE*)&ch, 7);
		message[idx++] = ch;
	} while (ch && idx < 127);
	std::string cleaned = Trim(message);
	strcpy_s(message, cleaned.c_str());
	if (message[0] == '/') {
		if (g_commandHandler->ProcessCommand(playerId, message))
			return 0;
	}
	else {
		if (!g_commandHandler->CheckChatCooldown(playerId))
			return 0;
	}
	return OriginalOnMessage(playerId, packetPtr);
}

static void __stdcall OnMessageRenderHook(int id, wchar_t* prefix, int msgContent, int cbfIndex, int isHost) {
	if (g_playerManager && id >= 100 && !g_playerManager->IsLogged(id))
		return;
	OriginalOnMessageRender(id, prefix, msgContent, cbfIndex, isHost);
}

static DWORD* __cdecl OnPlayerCreateHook(int* playerStruct, int playerId) {
	if (!g_playerConnectionWatcher->IsProcessedAID(playerId)) {
		*playerStruct = 0;
		thread createPlayer([playerId, playerStruct] {
			Sleep(200);
			char ip[128] = { 0 };
			if (GetClientAddress((void*)playerId, (int)ip, sizeof(ip))) {
				const char* name = (const char*)playerStruct + 6;
				g_playerConnectionWatcher->OnNewPlayer(std::string(name), std::string(ip), playerId);
			}
			});
		createPlayer.detach();
	}

	return OnPlayerCreate(playerStruct, playerId);
}

// ============================================================================
// Generování klíče
// ============================================================================
std::string GenerateRandomKey(int len = 16) {
	std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, (int)chars.size() - 1);
	std::string key;
	for (int i = 0; i < len; ++i) key += chars[dis(gen)];
	return key;
}

std::string LoadOrCreateEncryptionKey() {
	if (FileExists(KEY_FILE)) {
		std::ifstream f(KEY_FILE);
		std::string k; std::getline(f, k); f.close();
		if (!k.empty()) return k;
	}
	std::string k = GenerateRandomKey(256);
	std::ofstream f(KEY_FILE); f << k; f.close();
	return k;
}

// ============================================================================
// Hlavní vlákno DLL
// ============================================================================
DWORD WINAPI MainThread(LPVOID) {
	while (!(g_gameDLL = GetModuleHandleA("game.dll"))) {
		Sleep(100);
	}

	while (!(g_logsDLL = GetModuleHandleA("logs.dll"))) {
		Sleep(100);
	}

	Sleep(500);

	if (!g_gameDLL || !g_logsDLL) return 0;
	// AllocConsole();
	// FILE* file;
	// freopen_s(&file, "CONOUT$", "w", stdout);

	CreateDefaultConfigIfMissing();

	g_encryptionKey = LoadOrCreateEncryptionKey();

	auto pm = new PlayerManager();
	auto pdb = new PlayerDatabase();
	auto ini = new IniParser();
	auto msg = new MessageManager();
	g_playerManager = pm;
	g_playerDatabase = pdb;
	g_iniParser = ini;
	g_messageManager = msg;

	ini->Load(CONFIG_FILE);
	std::string dbPath = ini->GetValue("database_file");
	if (dbPath.empty() || dbPath == "." || dbPath == "./") dbPath = "players.dat";
	pdb->SetPath(dbPath);
	pdb->EnsureExists();

	auto loadInt = [&](const char* key, int& target, int minVal = 1) {
		std::string v = ini->GetValue(key);
		if (ini->IsInt(v)) { int val = std::stoi(v); if (val >= minVal) target = val; }
		};
	loadInt("min_password_length", g_minPasswordLength, 1);
	loadInt("max_password_length", g_maxPasswordLength, g_minPasswordLength);
	loadInt("max_password_tries_per_connection", g_maxLoginAttempts, 1);
	loadInt("chat_cooldown_time", g_chatCooldownSec, 0);

	OriginalOnMessage = (OnMessage_t)((uintptr_t)g_gameDLL + 0x163990);
	OriginalOnMessageRender = (OnMessageRender_t)((uintptr_t)g_gameDLL + 0x13E510);
	WriteBitsAligned = (WriteBitsAligned_t)((uintptr_t)g_gameDLL + 0x14B160);
	SendMessageToRemoteClient = (SendMessageToRemoteClient_t)((uintptr_t)g_gameDLL + 0x14B800);
	GetClientAddress = (GetClientAddress_t)((uintptr_t)g_gameDLL + 0x169E00);
	OnPlayerCreate = (OnPlayerCreate_t)((uintptr_t)g_gameDLL + 0x14D2E0);
	if (!OriginalOnMessage || !OriginalOnMessageRender || !WriteBitsAligned || !SendMessageToRemoteClient || !GetClientAddress || !OnPlayerCreate)
		return 0;

	g_commandHandler = new CommandHandler(pm, pdb, ini, msg);
	g_commandHandler->SetMinPasswordLength(g_minPasswordLength);
	g_commandHandler->SetMaxPasswordLength(g_maxPasswordLength);
	g_commandHandler->SetMaxLoginAttempts(g_maxLoginAttempts);
	g_commandHandler->SetChatCooldown(g_chatCooldownSec);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OriginalOnMessage, OnMessageHook);
	DetourAttach(&(PVOID&)OriginalOnMessageRender, OnMessageRenderHook);
	DetourAttach(&(PVOID&)OnPlayerCreate, OnPlayerCreateHook);
	DetourTransactionCommit();

	_beginthreadex(NULL, 0, [](void*)->unsigned { HookMonitor(NULL); return 0; }, NULL, 0, NULL);
	g_playerConnectionWatcher = new PlayerConnectionWatcher(pm, pdb, msg);

	CreateThread(
		NULL,
		0,
		[](LPVOID lpParam) -> DWORD WINAPI {
			auto* watcher = static_cast<PlayerConnectionWatcher*>(lpParam);
			watcher->Start();
			return 0;
		},
		g_playerConnectionWatcher,
		0,
		NULL
	);

	return 0;
}

// ============================================================================
// Vstupní bod
// ============================================================================
int _launch = 0;
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
	if (_launch++ == 0) {
		if (reason == DLL_PROCESS_ATTACH)
			CreateThread(NULL, 0, MainThread, hModule, 0, NULL);
	}
	return TRUE;
}
