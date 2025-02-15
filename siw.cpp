/* ========================================================================= **
** System Information Writer for Windows     (c) MhatXotic Design, 2016-2025 **
** https://github.com/mhatxotic/siw                              MIT Licence **
** ------------------------------------------------------------------------- **
** Permission is hereby granted, free of charge, to any person obtaining a   **
** copy of this software and associated documentation files                  **
** (the "Software"), to deal in the Software without restriction, including  **
** without limitation the rights to use, copy, modify, merge, publish,       **
** distribute, sublicense, and/or sell copies of the Software, and to permit **
** persons to whom the Software is furnished to do so, subject to the        **
** following conditions:                                                     **
** ------------------------------------------------------------------------- **
** The above copyright notice and this permission notice shall be included   **
** in all copies or substantial portions of the Software.                    **
** ------------------------------------------------------------------------- **
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS   **
** OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF                **
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN **
** NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,  **
** DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR     **
** OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE **
** USE OR OTHER DEALINGS IN THE SOFTWARE.                                    **
** ========================================================================= */
#define WIN32_LEAN_AND_MEAN            // Faster compilation of headers
#define _WIN32_WINNT            0x0600 // Windows Vista or later required
#define _WINVER           _WIN32_WINNT // Windows Vista or later required
/* ------------------------------------------------------------------------- */
#include <Windows.H>                   // Windows headers
#include <WS2TcpIP.H>                  // WinSock2 extension headers
#include <IPHlpAPI.H>                  // IP helper api headers
#include <Time.H>                      // Time headers
#include <StdIO.H>                     // Standard IO headers
#include <Sys/Types.H>                 // System types
#include <Sys/TimeB.H>                 // More system time stuff
#include <String.H>                    // String headers
#include <StdInt.H>                    // Portable types
#include <WinHTTP.H>                   // HTTP headers
/* ------------------------------------------------------------------------- */
#include <Exception>                   // Exception class
#include <String>                      // String class
#include <SStream>                     // StringStream classes
#include <List>                        // List class
#include <Map>                         // Map class
#include <Vector>                      // Vector class
/* ------------------------------------------------------------------------- */
using std::exception;                  // Make std::exception global namespace
using std::list;                       // Make std::list global namespace
using std::map;                        // Make std::map global namespace
using std::ostringstream;              // Make std::ostringstream global namesp
using std::string;                     // Make std::string global namespace
using std::vector;                     // Make std::vector global namespace
using std::wstring;                    // Make std::wstring global namespace
/* ------------------------------------------------------------------------- */
#pragma comment(lib, "IPHlpAPI")       // Link with IPHLPAPI.LIB
#pragma comment(lib, "Gdi32")          // Link with GDI32.LIB
#pragma comment(lib, "AdvApi32")       // Link with ADVAPI32.LIB
#pragma comment(lib, "WSock32")        // Link with WSOCK32.LIB
#pragma comment(lib, "User32")         // Link with USER32.LIB
#pragma comment(lib, "WinHTTP")        // Link with WINHTTP.LIB
/* ========================================================================= */
#define GFLAGS_NONE       0x0000000000 // No global flags
#define GFLAGS_STARTED    0x0000000001 // Program started
#define GFLAGS_EXIT       0x0000000002 // Program should exit
/* ========================================================================= */
#define UFLAGS_NONE       0x0000000000 // No update flags
#define UFLAGS_TMEUPDATED 0x0000000001 // Time was updated
#define UFLAGS_RAMUPDATED 0x0000000002 // Memory was updated
#define UFLAGS_CPUUPDATED 0x0000000004 // CPU was updated
#define UFLAGS_DISKA      0x0000000008 // Disk A: was updated
#define UFLAGS_DISKB      0x0000000010 // Disk B: was updated
#define UFLAGS_DISKC      0x0000000020 // Disk C: was updated
#define UFLAGS_DISKD      0x0000000040 // Disk D: was updated
#define UFLAGS_DISKE      0x0000000080 // Disk E: was updated
#define UFLAGS_DISKF      0x0000000100 // Disk F: was updated
#define UFLAGS_DISKG      0x0000000200 // Disk G: was updated
#define UFLAGS_DISKH      0x0000000400 // Disk H: was updated
#define UFLAGS_DISKI      0x0000000800 // Disk I: was updated
#define UFLAGS_DISKJ      0x0000001000 // Disk J: was updated
#define UFLAGS_DISKK      0x0000002000 // Disk K: was updated
#define UFLAGS_DISKL      0x0000004000 // Disk L: was updated
#define UFLAGS_DISKM      0x0000008000 // Disk M: was updated
#define UFLAGS_DISKN      0x0000010000 // Disk N: was updated
#define UFLAGS_DISKO      0x0000020000 // Disk O: was updated
#define UFLAGS_DISKP      0x0000040000 // Disk P: was updated
#define UFLAGS_DISKQ      0x0000080000 // Disk Q: was updated
#define UFLAGS_DISKR      0x0000100000 // Disk R: was updated
#define UFLAGS_DISKS      0x0000200000 // Disk S: was updated
#define UFLAGS_DISKT      0x0000400000 // Disk T: was updated
#define UFLAGS_DISKU      0x0000800000 // Disk U: was updated
#define UFLAGS_DISKV      0x0001000000 // Disk V: was updated
#define UFLAGS_DISKW      0x0002000000 // Disk W: was updated
#define UFLAGS_DISKX      0x0004000000 // Disk X: was updated
#define UFLAGS_DISKY      0x0008000000 // Disk Y: was updated
#define UFLAGS_DISKZ      0x0010000000 // Disk Z: was updated
#define UFLAGS_NETWORK    0x0020000000 // Network devices were updated
#define UFLAGS_NETCONN    0x0040000000 // Network connections were updated
#define UFLAGS_WINDOWS    0x0080000000 // Windows enumerated
#define UFLAGS_FWINDOW    0x0100000000 // Foreground window enumerated
/* ========================================================================= */
typedef struct _UBLK {
  string           strURL;             // The URL file to grab
  string           strOutFile;         // File to put data to
  uint32_t         ulSleepTime;        // Time to sleep before retry allowed
} UBLK, &RUBLK;                        // URL request information block
typedef map<const string,UBLK> UBLKS;  // URL request blocks
typedef UBLKS::iterator UBLKSI;        // URL blocks iterator
typedef map<const uint64_t,uint64_t> UMODLIST; // Last url modified list
typedef UMODLIST::iterator UMODLISTI;  // Last url modified list iterator
typedef struct _PKT {                  // Packet data
  char            *cpPacket;           // Packet chunk
  size_t           stSize;             // Size of chunk
} PKT, RPKT;
typedef struct _CMD { string strCmd, strFile; } CMD, &RCMD; // Command block
typedef list<const CMD> CMDS;          // Commands block
typedef CMDS::iterator CMDSI;          // Commands block iterator
typedef const string(*VIDFUNC)(void);  // Identifier callback function
typedef const bool(*VIDUFUNC)(void);   // Identifier update callback function
typedef struct _VID                    // Identifiers available to the user
{ /* ----------------------------------------------------------------------- */
  string           strCommand;         // Command name
  VIDFUNC          fpCallback;         // Callback function
  VIDUFUNC         fpUCallback;        // Update callback function
  uint64_t         uqFlag;             // Flag to set when stat updated
  /* ----------------------------------------------------------------------- */
} VID, *PVID, &RVID;                   // Static / Pointer / Reference
typedef vector<const VID> VIDS;        // Commands available to the user
typedef VIDS::iterator VIDSI;          // Commands available iterator
typedef struct _DISKINFO               // Disk information data
{ /* ----------------------------------------------------------------------- */
  uint64_t         uqDiskFree;         // Disk free data
  uint64_t         uqDiskTotal;        // Disk total data
  uint64_t         uqDiskUsed;         // Disk used data
  /* ----------------------------------------------------------------------- */
} DISKINFO, *PDISKINFO, &RDISKINFO;   // Static / Pointer / Reference
typedef struct _NETINFO                // Network information data
{ /* ----------------------------------------------------------------------- */
  uint64_t         uqNetInTotal;       // Total network bytes in
  uint64_t         uqNetIn;            // Network bandwidth in
  uint64_t         uqNetInLast;        // Network bandwidth in (last update)
  uint64_t         uqNetOutTotal;      // Total network bytes in
  uint64_t         uqNetOut;           // Network bandwidth out
  uint64_t         uqNetOutLast;       // Network bandwidth out (last update)
  /* ----------------------------------------------------------------------- */
} NETINFO, *PNETINFO, &RNETINFO;       // Static / Pointer / Reference
/* ========================================================================= */
char              *cpTimestamp = __TIMESTAMP__; // Compilation timestamp
unsigned int       uiBits = sizeof(void*)<<3;   // Bits version of application
static struct tm   tmData       = {0}; // Holds current time
char              *cpMerideumS =   0;  // Short time meridiem (a/p)
char              *cpMerideumL  =  0;  // Long time meridiem (AM/PM)
list<string>       lWindows;           // Window list
MEMORYSTATUSEX     memData      = {0}; // Holds current memory data
double             dCpuUsage    =  0;  // CPU usage
ostringstream      oData;              // String stream
DISKINFO           diskData[26] = {0}; // Disk data
NETINFO            netData[10]  = {0}; // Network information data
size_t             stNCserver   =  0;  // Network client connections total
size_t             stNCclient   =  0;  // Network server connections total
size_t             stNCtotal    =  0;  // Network connections total
string             strYTVideo;         // YouTube video being watched
string             strFWindow;         // Name of current foreground window
CRITICAL_SECTION   csHandle     = {0}; // Modifying url request list
CRITICAL_SECTION   csHandle2    = {0}; // Modifying url modified time list
UBLKS              ubBlocks;           // Url control blocks
UBLK               ubData;             // Url control block
UMODLIST           umData;             // Url modification time data
HINTERNET          hSession     =  0;  // WinHTTP session
CMDS               qCmds;              // Compiled commands list
VIDS               vidsData;           // Compiled identifier list
uint64_t           uqGFlags     =  0;  // Global flags
/* ========================================================================= */
#define            LOG_DEBUG         0 // Debug (trivial)
#define            LOG_NOTICE        1 // Notice (information)
#define            LOG_WARNING       2 // Warning (can continue)
#define            LOG_ERROR         3 // Error (must exit)
#define            LOG_X    __FILE__,__FUNCTION__,__LINE__,errno,GetLastError()
#ifdef DEBUG                         // Only show debug info when I need to
# define           LD(f,...)         Log(LOG_DEBUG,LOG_X,f,##__VA_ARGS__)
#else
# define           LD(f,...)
#endif                               // Other helpful logging macros
#define            LN(f,...)         Log(LOG_NOTICE,LOG_X,f,##__VA_ARGS__)
#define            LW(f,...)         Log(LOG_WARNING,LOG_X,f,##__VA_ARGS__)
#define            LE(f,...)         Log(LOG_ERROR,LOG_X,f,##__VA_ARGS__)
/* ========================================================================= */
const uint64_t uqCRCtab[256] = {
  0x0000000000000000,0x42F0E1EBA9EA3693,0x85E1C3D753D46D26,0xC711223CFA3E5BB5,
  0x493366450E42ECDF,0x0BC387AEA7A8DA4C,0xCCD2A5925D9681F9,0x8E224479F47CB76A,
  0x9266CC8A1C85D9BE,0xD0962D61B56FEF2D,0x17870F5D4F51B498,0x5577EEB6E6BB820B,
  0xDB55AACF12C73561,0x99A54B24BB2D03F2,0x5EB4691841135847,0x1C4488F3E8F96ED4,
  0x663D78FF90E185EF,0x24CD9914390BB37C,0xE3DCBB28C335E8C9,0xA12C5AC36ADFDE5A,
  0x2F0E1EBA9EA36930,0x6DFEFF5137495FA3,0xAAEFDD6DCD770416,0xE81F3C86649D3285,
  0xF45BB4758C645C51,0xB6AB559E258E6AC2,0x71BA77A2DFB03177,0x334A9649765A07E4,
  0xBD68D2308226B08E,0xFF9833DB2BCC861D,0x388911E7D1F2DDA8,0x7A79F00C7818EB3B,
  0xCC7AF1FF21C30BDE,0x8E8A101488293D4D,0x499B3228721766F8,0x0B6BD3C3DBFD506B,
  0x854997BA2F81E701,0xC7B97651866BD192,0x00A8546D7C558A27,0x4258B586D5BFBCB4,
  0x5E1C3D753D46D260,0x1CECDC9E94ACE4F3,0xDBFDFEA26E92BF46,0x990D1F49C77889D5,
  0x172F5B3033043EBF,0x55DFBADB9AEE082C,0x92CE98E760D05399,0xD03E790CC93A650A,
  0xAA478900B1228E31,0xE8B768EB18C8B8A2,0x2FA64AD7E2F6E317,0x6D56AB3C4B1CD584,
  0xE374EF45BF6062EE,0xA1840EAE168A547D,0x66952C92ECB40FC8,0x2465CD79455E395B,
  0x3821458AADA7578F,0x7AD1A461044D611C,0xBDC0865DFE733AA9,0xFF3067B657990C3A,
  0x711223CFA3E5BB50,0x33E2C2240A0F8DC3,0xF4F3E018F031D676,0xB60301F359DBE0E5,
  0xDA050215EA6C212F,0x98F5E3FE438617BC,0x5FE4C1C2B9B84C09,0x1D14202910527A9A,
  0x93366450E42ECDF0,0xD1C685BB4DC4FB63,0x16D7A787B7FAA0D6,0x5427466C1E109645,
  0x4863CE9FF6E9F891,0x0A932F745F03CE02,0xCD820D48A53D95B7,0x8F72ECA30CD7A324,
  0x0150A8DAF8AB144E,0x43A04931514122DD,0x84B16B0DAB7F7968,0xC6418AE602954FFB,
  0xBC387AEA7A8DA4C0,0xFEC89B01D3679253,0x39D9B93D2959C9E6,0x7B2958D680B3FF75,
  0xF50B1CAF74CF481F,0xB7FBFD44DD257E8C,0x70EADF78271B2539,0x321A3E938EF113AA,
  0x2E5EB66066087D7E,0x6CAE578BCFE24BED,0xABBF75B735DC1058,0xE94F945C9C3626CB,
  0x676DD025684A91A1,0x259D31CEC1A0A732,0xE28C13F23B9EFC87,0xA07CF2199274CA14,
  0x167FF3EACBAF2AF1,0x548F120162451C62,0x939E303D987B47D7,0xD16ED1D631917144,
  0x5F4C95AFC5EDC62E,0x1DBC74446C07F0BD,0xDAAD56789639AB08,0x985DB7933FD39D9B,
  0x84193F60D72AF34F,0xC6E9DE8B7EC0C5DC,0x01F8FCB784FE9E69,0x43081D5C2D14A8FA,
  0xCD2A5925D9681F90,0x8FDAB8CE70822903,0x48CB9AF28ABC72B6,0x0A3B7B1923564425,
  0x70428B155B4EAF1E,0x32B26AFEF2A4998D,0xF5A348C2089AC238,0xB753A929A170F4AB,
  0x3971ED50550C43C1,0x7B810CBBFCE67552,0xBC902E8706D82EE7,0xFE60CF6CAF321874,
  0xE224479F47CB76A0,0xA0D4A674EE214033,0x67C58448141F1B86,0x253565A3BDF52D15,
  0xAB1721DA49899A7F,0xE9E7C031E063ACEC,0x2EF6E20D1A5DF759,0x6C0603E6B3B7C1CA,
  0xF6FAE5C07D3274CD,0xB40A042BD4D8425E,0x731B26172EE619EB,0x31EBC7FC870C2F78,
  0xBFC9838573709812,0xFD39626EDA9AAE81,0x3A28405220A4F534,0x78D8A1B9894EC3A7,
  0x649C294A61B7AD73,0x266CC8A1C85D9BE0,0xE17DEA9D3263C055,0xA38D0B769B89F6C6,
  0x2DAF4F0F6FF541AC,0x6F5FAEE4C61F773F,0xA84E8CD83C212C8A,0xEABE6D3395CB1A19,
  0x90C79D3FEDD3F122,0xD2377CD44439C7B1,0x15265EE8BE079C04,0x57D6BF0317EDAA97,
  0xD9F4FB7AE3911DFD,0x9B041A914A7B2B6E,0x5C1538ADB04570DB,0x1EE5D94619AF4648,
  0x02A151B5F156289C,0x4051B05E58BC1E0F,0x87409262A28245BA,0xC5B073890B687329,
  0x4B9237F0FF14C443,0x0962D61B56FEF2D0,0xCE73F427ACC0A965,0x8C8315CC052A9FF6,
  0x3A80143F5CF17F13,0x7870F5D4F51B4980,0xBF61D7E80F251235,0xFD913603A6CF24A6,
  0x73B3727A52B393CC,0x31439391FB59A55F,0xF652B1AD0167FEEA,0xB4A25046A88DC879,
  0xA8E6D8B54074A6AD,0xEA16395EE99E903E,0x2D071B6213A0CB8B,0x6FF7FA89BA4AFD18,
  0xE1D5BEF04E364A72,0xA3255F1BE7DC7CE1,0x64347D271DE22754,0x26C49CCCB40811C7,
  0x5CBD6CC0CC10FAFC,0x1E4D8D2B65FACC6F,0xD95CAF179FC497DA,0x9BAC4EFC362EA149,
  0x158E0A85C2521623,0x577EEB6E6BB820B0,0x906FC95291867B05,0xD29F28B9386C4D96,
  0xCEDBA04AD0952342,0x8C2B41A1797F15D1,0x4B3A639D83414E64,0x09CA82762AAB78F7,
  0x87E8C60FDED7CF9D,0xC51827E4773DF90E,0x020905D88D03A2BB,0x40F9E43324E99428,
  0x2CFFE7D5975E55E2,0x6E0F063E3EB46371,0xA91E2402C48A38C4,0xEBEEC5E96D600E57,
  0x65CC8190991CB93D,0x273C607B30F68FAE,0xE02D4247CAC8D41B,0xA2DDA3AC6322E288,
  0xBE992B5F8BDB8C5C,0xFC69CAB42231BACF,0x3B78E888D80FE17A,0x7988096371E5D7E9,
  0xF7AA4D1A85996083,0xB55AACF12C735610,0x724B8ECDD64D0DA5,0x30BB6F267FA73B36,
  0x4AC29F2A07BFD00D,0x08327EC1AE55E69E,0xCF235CFD546BBD2B,0x8DD3BD16FD818BB8,
  0x03F1F96F09FD3CD2,0x41011884A0170A41,0x86103AB85A2951F4,0xC4E0DB53F3C36767,
  0xD8A453A01B3A09B3,0x9A54B24BB2D03F20,0x5D45907748EE6495,0x1FB5719CE1045206,
  0x919735E51578E56C,0xD367D40EBC92D3FF,0x1476F63246AC884A,0x568617D9EF46BED9,
  0xE085162AB69D5E3C,0xA275F7C11F7768AF,0x6564D5FDE549331A,0x279434164CA30589,
  0xA9B6706FB8DFB2E3,0xEB46918411358470,0x2C57B3B8EB0BDFC5,0x6EA7525342E1E956,
  0x72E3DAA0AA188782,0x30133B4B03F2B111,0xF7021977F9CCEAA4,0xB5F2F89C5026DC37,
  0x3BD0BCE5A45A6B5D,0x79205D0E0DB05DCE,0xBE317F32F78E067B,0xFCC19ED95E6430E8,
  0x86B86ED5267CDBD3,0xC4488F3E8F96ED40,0x0359AD0275A8B6F5,0x41A94CE9DC428066,
  0xCF8B0890283E370C,0x8D7BE97B81D4019F,0x4A6ACB477BEA5A2A,0x089A2AACD2006CB9,
  0x14DEA25F3AF9026D,0x562E43B4931334FE,0x913F6188692D6F4B,0xD3CF8063C0C759D8,
  0x5DEDC41A34BBEEB2,0x1F1D25F19D51D821,0xD80C07CD676F8394,0x9AFCE626CE85B507
};
/* == String Format Functions ============================================== */
inline const string FormatArguments(const string &strFormat, va_list vlArgs)
{ // Allocate memory for buffer. We can reuse the vlArgs in VC unlike unix.
  const string strString(_vscprintf(strFormat.c_str(), vlArgs), 0);
  // Format buffer
  _vsnprintf_s((char*)strString.c_str(), strString.size()+1, strString.size(),
    strFormat.c_str(), vlArgs);
  // Return string
  return strString;
}
/* ========================================================================= */
inline const string FormatString(const char *cpFormat, ...)
{ // Create pointer to arguments
  va_list vlArgs;
  // Get pointer to arguments list (...)
  va_start(vlArgs, cpFormat);
  // Format arguments list
  const string strString = FormatArguments(cpFormat, vlArgs);
  // Done with arguments list
  va_end(vlArgs);
  // Return result
  return strString;
}
/* ========================================================================= */
inline const void Log(const unsigned int uiType, const char *cpFile,
  const char *cpFunction, const unsigned int uiLine, const unsigned int uiERN,
  const unsigned int uiGLE, const char *cpFormat, ...)
{ // Types
  static const char *cpTypes[] = { "DEBUG","NOTICE","WARNING","ERROR" };
  // Pointer to ... part of arguments
  static va_list vlArgs;
  // Set pointer to ... part of arguments
  va_start(vlArgs, cpFormat);
  // Format the buffer
  static string strFmt; strFmt = FormatArguments(cpFormat, vlArgs);
  // Done with arguments list
  va_end(vlArgs);
  // Set default string if empty
  if(strFmt.empty()) strFmt = cpFormat;
  // For time
  static SYSTEMTIME stData;
  // Get local system time
  GetLocalTime(&stData);
  // Start building buffer
  fputs(FormatString("%04u-%02u-%02u %02u:%02u:%02u.%03u %-7s %-32s %5u %5u %3u %s\n",
    stData.wYear, stData.wMonth, stData.wDay, stData.wHour,
    stData.wMinute, stData.wSecond, stData.wMilliseconds, cpTypes[uiType],
    FormatString("%s:%s:%u", cpFile, cpFunction, uiLine)
      .c_str(), GetCurrentThreadId(), uiGLE, uiERN, strFmt.c_str()).c_str(),
    stderr);
  // If was an error throw it
  if(uiType == LOG_ERROR) throw 0;
}
/* ========================================================================= */
inline uint64_t CRC64(uint64_t uqCRC, uint8_t *ubPtr, size_t stSize)
{ // Do calculations
  while(stSize--) uqCRC = uqCRCtab[(uint8_t)uqCRC^ubPtr[stSize]]^(uqCRC>>8);
  // Return result
  return uqCRC;
}
/* ========================================================================= */
inline const bool viducCPU(void)
{ // Storage for last and current system times
  static uint64_t ktIL=0, ktKL=0, ktUL=0, ktI=0, ktK=0, ktU=0;
  // Get CPU info and bail if failed
  if(!GetSystemTimes((LPFILETIME)&ktI, (LPFILETIME)&ktK, (LPFILETIME)&ktU))
    return false;
  // Storage for CPU usages
  static uint64_t uqCpuIdle, uqCpuUser, uqCpuKernel, uqCpuSys;
  // Calculate CPU usage
  uqCpuIdle = ktI-ktIL;
  uqCpuUser = ktU-ktUL;
  uqCpuKernel = ktK-ktKL;
  // Calculate system time
  uqCpuSys = uqCpuKernel + uqCpuUser;
  // Calculate cpu usage
  dCpuUsage = ((double)(uqCpuSys-uqCpuIdle)*100/uqCpuSys);
  // Update last values
  ktIL = ktI, ktUL = ktU, ktKL = ktK;
  // OK
  return true;
}
/* ========================================================================= */
inline const bool viducRAM(void)
  { return GlobalMemoryStatusEx(&memData) ? true : false; }
/* ========================================================================= */
inline const bool viducDateTime(void)
{ // Get time
  static __time64_t tStamp;
  tStamp = _time64(0);
  _localtime64_s(&tmData, &tStamp);
  cpMerideumS = tmData.tm_hour < 12 ? "a" : "p";
  cpMerideumL = tmData.tm_hour < 12 ? "AM" : "PM";
  // Succeeded
  return true;
}
/* ========================================================================= */
template<typename T> inline const string ITA(const T tValue)
  { oData.str(""); oData.clear(); oData << tValue; return oData.str(); }
template<typename T> inline const string CLZ(const T tValue)
  { return string(tValue<10?"0":"")+ITA<T>(tValue); }
/* ========================================================================= */
inline const string vidcMerideumShort(void) { return cpMerideumS; }
inline const string vidcMerideumLong(void) { return cpMerideumL; }
inline const string vidcDay(void) { return CLZ<int>(tmData.tm_mday); }
inline const string vidcLDay(void) { return ITA<int>(tmData.tm_mday); }
inline const string vidcMonth(void) { return CLZ<int>(tmData.tm_mon); }
inline const string vidcLMonth(void) { return ITA<int>(tmData.tm_mon); }
inline const string vidcYear(void) { return CLZ<int>(tmData.tm_year%100); }
inline const string vidcFYear(void) { return ITA<int>(tmData.tm_year+1900); }
inline const string vidcHour(void) { return CLZ<int>(tmData.tm_hour); }
inline const string vidcLHour(void) { return ITA<int>(tmData.tm_hour%12); }
inline const string vidcMin(void) { return CLZ<int>(tmData.tm_min); }
inline const string vidcLMin(void) { return ITA<int>(tmData.tm_min); }
inline const string vidcSecond(void) { return CLZ<int>(tmData.tm_sec); }
inline const string vidcLSec(void) { return ITA<int>(tmData.tm_sec); }
/* ------------------------------------------------------------------------- */
inline const string vidcCPUUsage(void) { return ITA<double>(dCpuUsage); }
/* ------------------------------------------------------------------------- */
inline const string MHRB(const uint64_t stValue)
{ // Return human readable bytes value
  if(stValue >= 1073741824) return ITA<double>((double)stValue/1073741824)+"GB";
  if(stValue >= 1048576) return ITA<double>((double)stValue/1048576)+"MB";
  if(stValue >= 1024) return ITA<double>((double)stValue/1024)+"KB";
  return ITA<uint64_t>(stValue)+"B";
}
/* ------------------------------------------------------------------------- */
inline const string vidcRAMTotal(void) { return MHRB(memData.ullTotalPhys); }
inline const string vidcRAMFree(void) { return MHRB(memData.ullAvailPhys); }
inline const string vidcRAMUsed(void) { return MHRB(memData.ullTotalPhys - memData.ullAvailPhys); }
inline const string vidcRAMFreeP(void) { return ITA<double>((double)memData.ullAvailPhys / memData.ullTotalPhys * 100); }
inline const string vidcRAMUsedP(void) { return ITA<double>((double)(memData.ullTotalPhys - memData.ullAvailPhys) / memData.ullTotalPhys * 100); }
/* ========================================================================= */
inline const bool viducNetConn(void)
{ // Reset statistics
  stNCserver = stNCclient = stNCtotal = 0;
  // Get size of connection table
  PMIB_TCPTABLE2 pTcpTable = NULL;
  ULONG dwSize = 0;
  // Get size of tcp table structuresss
  if(GetTcpTable2(pTcpTable, &dwSize, FALSE)!=ERROR_INSUFFICIENT_BUFFER)
    return false;
  // Alocate memory for table
  pTcpTable = (PMIB_TCPTABLE2)new char[dwSize];
  if(GetTcpTable2(pTcpTable, &dwSize, FALSE)==NO_ERROR)
  { // Get reference to table
    const MIB_TCPTABLE2 &tcpTable = *pTcpTable;
    // List of servers
    list<MIB_TCPROW2> sServers;
    // For each entry
    for(DWORD dwIndex = 0; dwIndex < tcpTable.dwNumEntries; ++dwIndex)
    { // Get reference to table
      const MIB_TCPROW2 &tcpData = tcpTable.table[dwIndex];
      if(tcpData.dwState == MIB_TCP_STATE_LISTEN)
        sServers.push_back(tcpData);
    }
    // For each entry again (now we have the list of servers
    for(DWORD dwIndex = 0; dwIndex < tcpTable.dwNumEntries; ++dwIndex)
    { // Get reference to table
      const MIB_TCPROW2 &tcpData = tcpTable.table[dwIndex];
      // Not establed? Ignore
      if(tcpData.dwState != MIB_TCP_STATE_ESTAB) continue;
      // Is server connection
      unsigned int uiIsSconn = 0;
      // Enumerate server conncetions
      for(list<MIB_TCPROW2>::iterator sItem = sServers.begin();
                                      sItem != sServers.end();
                                    ++sItem)
      { // Get reference to server address
        const MIB_TCPROW2 &tcpSData = *sItem;
        // Try next server if not matched
        if(tcpSData.dwLocalAddr != tcpData.dwLocalAddr ||
           tcpSData.dwLocalPort != tcpData.dwLocalPort) continue;
        // Increase server connections
        ++stNCserver;
        // Was a server connection
        uiIsSconn = 1;
        // Found. No need to carry on checking
        break;
      }
      // Not a server connection and is established? Is a client connection
      if(!uiIsSconn) ++stNCclient;
    }
    // Set total connections;
    stNCtotal = stNCclient + stNCserver;
  }
  // Free memory
  delete []pTcpTable;
  // Success
  return true;
}
/* ========================================================================= */
inline const string vidcNetConnCount(void) { return ITA<size_t>(stNCtotal); }
inline const string vidcNetCliCount(void) { return ITA<size_t>(stNCclient); }
inline const string vidcNetSrvCount(void) { return ITA<size_t>(stNCserver); }
/* ========================================================================= */
inline const bool viducNet(void)
{ // Get size of interface table
  MIB_IF_TABLE2 *pIfTable;
  if(GetIfTable2(&pIfTable) == ERROR_NOT_ENOUGH_MEMORY) return false;
  // Reference the if table
  const MIB_IF_TABLE2 &rIfTable = *pIfTable;
  // Calculate maximum number of adapters
  const size_t stMax = min(10, rIfTable.NumEntries);
  // Walk table
  for(size_t stIndex = 0; stIndex < stMax; ++stIndex)
  { // Alias entry and netdata entries
    const MIB_IF_ROW2 &mData = rIfTable.Table[stIndex];
    const RNETINFO nData = netData[stIndex];
    // Write in bytes
    nData.uqNetInTotal = mData.InUcastOctets;
    nData.uqNetOutTotal = mData.OutUcastOctets;
    // Calculate bandwidth
    nData.uqNetIn = nData.uqNetInTotal - nData.uqNetInLast;
    nData.uqNetOut = nData.uqNetOutTotal - nData.uqNetOutLast;
    // Update last counters
    nData.uqNetInLast = nData.uqNetInTotal;
    nData.uqNetOutLast = nData.uqNetOutTotal;
  }
  // Remove
  FreeMibTable(pIfTable);
  // Done
  return true;
}
/* ------------------------------------------------------------------------- */
inline const string vidcNetInTotal0(void) { return MHRB(netData[0].uqNetInTotal); }
inline const string vidcNetOutTotal0(void) { return MHRB(netData[0].uqNetOutTotal); }
inline const string vidcNetInTraffic0(void) { return MHRB(netData[0].uqNetIn); }
inline const string vidcNetOutTraffic0(void) { return MHRB(netData[0].uqNetOut); }
inline const string vidcNetInTotal1(void) { return MHRB(netData[1].uqNetInTotal); }
inline const string vidcNetOutTotal1(void) { return MHRB(netData[1].uqNetOutTotal); }
inline const string vidcNetInTraffic1(void) { return MHRB(netData[1].uqNetIn); }
inline const string vidcNetOutTraffic1(void) { return MHRB(netData[1].uqNetOut); }
inline const string vidcNetInTotal2(void) { return MHRB(netData[2].uqNetInTotal); }
inline const string vidcNetOutTotal2(void) { return MHRB(netData[2].uqNetOutTotal); }
inline const string vidcNetInTraffic2(void) { return MHRB(netData[2].uqNetIn); }
inline const string vidcNetOutTraffic2(void) { return MHRB(netData[2].uqNetOut); }
inline const string vidcNetInTotal3(void) { return MHRB(netData[3].uqNetInTotal); }
inline const string vidcNetOutTotal3(void) { return MHRB(netData[3].uqNetOutTotal); }
inline const string vidcNetInTraffic3(void) { return MHRB(netData[3].uqNetIn); }
inline const string vidcNetOutTraffic3(void) { return MHRB(netData[3].uqNetOut); }
inline const string vidcNetInTotal4(void) { return MHRB(netData[4].uqNetInTotal); }
inline const string vidcNetOutTotal4(void) { return MHRB(netData[4].uqNetOutTotal); }
inline const string vidcNetInTraffic4(void) { return MHRB(netData[4].uqNetIn); }
inline const string vidcNetOutTraffic4(void) { return MHRB(netData[4].uqNetOut); }
inline const string vidcNetInTotal5(void) { return MHRB(netData[5].uqNetInTotal); }
inline const string vidcNetOutTotal5(void) { return MHRB(netData[5].uqNetOutTotal); }
inline const string vidcNetInTraffic5(void) { return MHRB(netData[5].uqNetIn); }
inline const string vidcNetOutTraffic5(void) { return MHRB(netData[5].uqNetOut); }
inline const string vidcNetInTotal6(void) { return MHRB(netData[6].uqNetInTotal); }
inline const string vidcNetOutTotal6(void) { return MHRB(netData[6].uqNetOutTotal); }
inline const string vidcNetInTraffic6(void) { return MHRB(netData[6].uqNetIn); }
inline const string vidcNetOutTraffic6(void) { return MHRB(netData[6].uqNetOut); }
inline const string vidcNetInTotal7(void) { return MHRB(netData[7].uqNetInTotal); }
inline const string vidcNetOutTotal7(void) { return MHRB(netData[7].uqNetOutTotal); }
inline const string vidcNetInTraffic7(void) { return MHRB(netData[7].uqNetIn); }
inline const string vidcNetOutTraffic7(void) { return MHRB(netData[7].uqNetOut); }
inline const string vidcNetInTotal8(void) { return MHRB(netData[8].uqNetInTotal); }
inline const string vidcNetOutTotal8(void) { return MHRB(netData[8].uqNetOutTotal); }
inline const string vidcNetInTraffic8(void) { return MHRB(netData[8].uqNetIn); }
inline const string vidcNetOutTraffic8(void) { return MHRB(netData[8].uqNetOut); }
inline const string vidcNetInTotal9(void) { return MHRB(netData[9].uqNetInTotal); }
inline const string vidcNetOutTotal9(void) { return MHRB(netData[9].uqNetOutTotal); }
inline const string vidcNetInTraffic9(void) { return MHRB(netData[9].uqNetIn); }
inline const string vidcNetOutTraffic9(void) { return MHRB(netData[9].uqNetOut); }
/* ========================================================================= */
inline const bool viducDisk(const size_t stDisk)
{ // Sanity check
  if(stDisk >= 26) return false;
  // Get disk
  const uint8_t ucDisk = (uint8_t)stDisk+'A';
  // Get disk data
  const RDISKINFO diskItem = diskData[stDisk];
  // Get data
  if(GetDiskFreeSpaceEx(string(string((char*)&ucDisk, 1)+":\\").c_str(),
    NULL, (PULARGE_INTEGER)&diskItem.uqDiskTotal,
          (PULARGE_INTEGER)&diskItem.uqDiskFree) == FALSE) return false;
  // Calculate used
  diskItem.uqDiskUsed = diskItem.uqDiskTotal - diskItem.uqDiskFree;
  // OK
  return true;
}
/* ------------------------------------------------------------------------- */
inline const bool viducDiskA(void) { return viducDisk(0); }
inline const bool viducDiskB(void) { return viducDisk(1); }
inline const bool viducDiskC(void) { return viducDisk(2); }
inline const bool viducDiskD(void) { return viducDisk(3); }
inline const bool viducDiskE(void) { return viducDisk(4); }
inline const bool viducDiskF(void) { return viducDisk(5); }
inline const bool viducDiskG(void) { return viducDisk(6); }
inline const bool viducDiskH(void) { return viducDisk(7); }
inline const bool viducDiskI(void) { return viducDisk(8); }
inline const bool viducDiskJ(void) { return viducDisk(9); }
inline const bool viducDiskK(void) { return viducDisk(10); }
inline const bool viducDiskL(void) { return viducDisk(11); }
inline const bool viducDiskM(void) { return viducDisk(12); }
inline const bool viducDiskN(void) { return viducDisk(13); }
inline const bool viducDiskO(void) { return viducDisk(14); }
inline const bool viducDiskP(void) { return viducDisk(15); }
inline const bool viducDiskQ(void) { return viducDisk(16); }
inline const bool viducDiskR(void) { return viducDisk(17); }
inline const bool viducDiskS(void) { return viducDisk(18); }
inline const bool viducDiskT(void) { return viducDisk(19); }
inline const bool viducDiskU(void) { return viducDisk(20); }
inline const bool viducDiskV(void) { return viducDisk(21); }
inline const bool viducDiskW(void) { return viducDisk(22); }
inline const bool viducDiskX(void) { return viducDisk(23); }
inline const bool viducDiskY(void) { return viducDisk(24); }
inline const bool viducDiskZ(void) { return viducDisk(25); }
/* ------------------------------------------------------------------------- */
inline const string vidcDiskFreeA(void) { return MHRB(diskData[0].uqDiskFree); }
inline const string vidcDiskFreeB(void) { return MHRB(diskData[1].uqDiskFree); }
inline const string vidcDiskFreeC(void) { return MHRB(diskData[2].uqDiskFree); }
inline const string vidcDiskFreeD(void) { return MHRB(diskData[3].uqDiskFree); }
inline const string vidcDiskFreeE(void) { return MHRB(diskData[4].uqDiskFree); }
inline const string vidcDiskFreeF(void) { return MHRB(diskData[5].uqDiskFree); }
inline const string vidcDiskFreeG(void) { return MHRB(diskData[6].uqDiskFree); }
inline const string vidcDiskFreeH(void) { return MHRB(diskData[7].uqDiskFree); }
inline const string vidcDiskFreeI(void) { return MHRB(diskData[8].uqDiskFree); }
inline const string vidcDiskFreeJ(void) { return MHRB(diskData[9].uqDiskFree); }
inline const string vidcDiskFreeK(void) { return MHRB(diskData[10].uqDiskFree); }
inline const string vidcDiskFreeL(void) { return MHRB(diskData[11].uqDiskFree); }
inline const string vidcDiskFreeM(void) { return MHRB(diskData[12].uqDiskFree); }
inline const string vidcDiskFreeN(void) { return MHRB(diskData[13].uqDiskFree); }
inline const string vidcDiskFreeO(void) { return MHRB(diskData[14].uqDiskFree); }
inline const string vidcDiskFreeP(void) { return MHRB(diskData[15].uqDiskFree); }
inline const string vidcDiskFreeQ(void) { return MHRB(diskData[16].uqDiskFree); }
inline const string vidcDiskFreeR(void) { return MHRB(diskData[17].uqDiskFree); }
inline const string vidcDiskFreeS(void) { return MHRB(diskData[18].uqDiskFree); }
inline const string vidcDiskFreeT(void) { return MHRB(diskData[19].uqDiskFree); }
inline const string vidcDiskFreeU(void) { return MHRB(diskData[20].uqDiskFree); }
inline const string vidcDiskFreeV(void) { return MHRB(diskData[21].uqDiskFree); }
inline const string vidcDiskFreeW(void) { return MHRB(diskData[22].uqDiskFree); }
inline const string vidcDiskFreeX(void) { return MHRB(diskData[23].uqDiskFree); }
inline const string vidcDiskFreeY(void) { return MHRB(diskData[24].uqDiskFree); }
inline const string vidcDiskFreeZ(void) { return MHRB(diskData[25].uqDiskFree); }
/* ------------------------------------------------------------------------- */
inline const string vidcDiskTotalA(void) { return MHRB(diskData[0].uqDiskTotal); }
inline const string vidcDiskTotalB(void) { return MHRB(diskData[1].uqDiskTotal); }
inline const string vidcDiskTotalC(void) { return MHRB(diskData[2].uqDiskTotal); }
inline const string vidcDiskTotalD(void) { return MHRB(diskData[3].uqDiskTotal); }
inline const string vidcDiskTotalE(void) { return MHRB(diskData[4].uqDiskTotal); }
inline const string vidcDiskTotalF(void) { return MHRB(diskData[5].uqDiskTotal); }
inline const string vidcDiskTotalG(void) { return MHRB(diskData[6].uqDiskTotal); }
inline const string vidcDiskTotalH(void) { return MHRB(diskData[7].uqDiskTotal); }
inline const string vidcDiskTotalI(void) { return MHRB(diskData[8].uqDiskTotal); }
inline const string vidcDiskTotalJ(void) { return MHRB(diskData[9].uqDiskTotal); }
inline const string vidcDiskTotalK(void) { return MHRB(diskData[10].uqDiskTotal); }
inline const string vidcDiskTotalL(void) { return MHRB(diskData[11].uqDiskTotal); }
inline const string vidcDiskTotalM(void) { return MHRB(diskData[12].uqDiskTotal); }
inline const string vidcDiskTotalN(void) { return MHRB(diskData[13].uqDiskTotal); }
inline const string vidcDiskTotalO(void) { return MHRB(diskData[14].uqDiskTotal); }
inline const string vidcDiskTotalP(void) { return MHRB(diskData[15].uqDiskTotal); }
inline const string vidcDiskTotalQ(void) { return MHRB(diskData[16].uqDiskTotal); }
inline const string vidcDiskTotalR(void) { return MHRB(diskData[17].uqDiskTotal); }
inline const string vidcDiskTotalS(void) { return MHRB(diskData[18].uqDiskTotal); }
inline const string vidcDiskTotalT(void) { return MHRB(diskData[19].uqDiskTotal); }
inline const string vidcDiskTotalU(void) { return MHRB(diskData[20].uqDiskTotal); }
inline const string vidcDiskTotalV(void) { return MHRB(diskData[21].uqDiskTotal); }
inline const string vidcDiskTotalW(void) { return MHRB(diskData[22].uqDiskTotal); }
inline const string vidcDiskTotalX(void) { return MHRB(diskData[23].uqDiskTotal); }
inline const string vidcDiskTotalY(void) { return MHRB(diskData[24].uqDiskTotal); }
inline const string vidcDiskTotalZ(void) { return MHRB(diskData[25].uqDiskTotal); }
/* ------------------------------------------------------------------------- */
inline const string vidcDiskUsedA(void) { return MHRB(diskData[0].uqDiskUsed); }
inline const string vidcDiskUsedB(void) { return MHRB(diskData[1].uqDiskUsed); }
inline const string vidcDiskUsedC(void) { return MHRB(diskData[2].uqDiskUsed); }
inline const string vidcDiskUsedD(void) { return MHRB(diskData[3].uqDiskUsed); }
inline const string vidcDiskUsedE(void) { return MHRB(diskData[4].uqDiskUsed); }
inline const string vidcDiskUsedF(void) { return MHRB(diskData[5].uqDiskUsed); }
inline const string vidcDiskUsedG(void) { return MHRB(diskData[6].uqDiskUsed); }
inline const string vidcDiskUsedH(void) { return MHRB(diskData[7].uqDiskUsed); }
inline const string vidcDiskUsedI(void) { return MHRB(diskData[8].uqDiskUsed); }
inline const string vidcDiskUsedJ(void) { return MHRB(diskData[9].uqDiskUsed); }
inline const string vidcDiskUsedK(void) { return MHRB(diskData[10].uqDiskUsed); }
inline const string vidcDiskUsedL(void) { return MHRB(diskData[11].uqDiskUsed); }
inline const string vidcDiskUsedM(void) { return MHRB(diskData[12].uqDiskUsed); }
inline const string vidcDiskUsedN(void) { return MHRB(diskData[13].uqDiskUsed); }
inline const string vidcDiskUsedO(void) { return MHRB(diskData[14].uqDiskUsed); }
inline const string vidcDiskUsedP(void) { return MHRB(diskData[15].uqDiskUsed); }
inline const string vidcDiskUsedQ(void) { return MHRB(diskData[16].uqDiskUsed); }
inline const string vidcDiskUsedR(void) { return MHRB(diskData[17].uqDiskUsed); }
inline const string vidcDiskUsedS(void) { return MHRB(diskData[18].uqDiskUsed); }
inline const string vidcDiskUsedT(void) { return MHRB(diskData[19].uqDiskUsed); }
inline const string vidcDiskUsedU(void) { return MHRB(diskData[20].uqDiskUsed); }
inline const string vidcDiskUsedV(void) { return MHRB(diskData[21].uqDiskUsed); }
inline const string vidcDiskUsedW(void) { return MHRB(diskData[22].uqDiskUsed); }
inline const string vidcDiskUsedX(void) { return MHRB(diskData[23].uqDiskUsed); }
inline const string vidcDiskUsedY(void) { return MHRB(diskData[24].uqDiskUsed); }
inline const string vidcDiskUsedZ(void) { return MHRB(diskData[25].uqDiskUsed); }
/* ========================================================================= */
inline const string charCarriageReturn(void) { return "\r"; }
inline const string charLineFeed(void) { return "\n"; }
/* ========================================================================= */
inline BOOL CALLBACK EnumWindowsProc(HWND hH, LPARAM)
{ // Create storage for window and class info
  static char caCName[1024], caWName[1024];
  // Get classname and ignore classnames <= 16 characters
  if(GetClassName(hH, (LPSTR)caCName, sizeof(caCName))<=16) return 1;
  // Get window name and ignore classnames <= 13 characters
  if(GetWindowText(hH, (LPSTR)caWName, sizeof(caWName))<=13) return 1;
  // Is a browser window? Using INT64 comparisons for optimum speed.
  if((*(int64_t*)caCName == 0x57616c6c697a6f4d &&     // Mozilla Firefox 29
     *(int64_t*)(caCName+8) == 0x616c43776f646e69) || // 'MozillaWindowCla'(ss)
     (*(int64_t*)caCName == 0x575f656d6f726843 &&     // Google Chrome 34
     *(int64_t*)(caCName+8) == 0x6e69577465676469) || // 'ChromeWidget_Win'(N)
     (*(int64_t*)caCName == 0x5461625468756d62 &&     // Internet Explorer 11
     *(int64_t*)(caCName+8) == 0x6e61696c57696e64))   // 'TabThumbnailWind'(ow)
  { // Find YouTube in title
    char *cpTmp = strstr(caWName, " - YouTube");
    // Is a YouTube window and playing?
    if(cpTmp && *(int16_t*)caWName == ' ?')
    { // Truncate
      *cpTmp = 0;
      // Only write if playing.
      strYTVideo = caWName+2;
    }
  }
  // Carry on enumerating
  return 1;
}
/* ========================================================================= */
inline const string vidcForeWindow(void) { return strFWindow; }
/* ------------------------------------------------------------------------- */
inline const bool viducFWindow(void)
{ // Storage for current window name
  strFWindow.resize(1024);
  // No window title?
  strFWindow = GetWindowText(GetForegroundWindow(), (LPSTR)strFWindow.c_str(),
    (int)strFWindow.size())>0 ? strFWindow : "No active window";
  // Find firefox
  return true;
}
/* ========================================================================= */
inline const bool viducWindows(void)
{ // Reset youtube video
  strYTVideo = "Not playing";
  // Enumerate windows
  if(!EnumWindows(EnumWindowsProc, NULL)) return false;
  // Find firefox
  return true;
}
/* ------------------------------------------------------------------------- */
inline const string vidcYouTubeWatch(void) { return strYTVideo; }
/* ========================================================================= */
inline const int InitIdentifiers(void)
{ /* ----------------------------------------------------------------------- */
  const VID vidData[]=
  { /* --------------------------------------------------------------------- */
    "$CR",   charCarriageReturn, NULL,          UFLAGS_NONE,
    "$LF",   charLineFeed,       NULL,          UFLAGS_NONE,
    /* --------------------------------------------------------------------- */
    "$YT",   vidcYouTubeWatch,   viducWindows,  UFLAGS_WINDOWS,
    "$FW",   vidcForeWindow,     viducFWindow,  UFLAGS_FWINDOW,
    /* --------------------------------------------------------------------- */
    "$CU",   vidcCPUUsage,       viducCPU,      UFLAGS_CPUUPDATED,
    /* --------------------------------------------------------------------- */
    "$MT",   vidcRAMTotal,       viducRAM,      UFLAGS_RAMUPDATED,
    "$MFP",  vidcRAMFreeP,       viducRAM,      UFLAGS_RAMUPDATED,
    "$MF",   vidcRAMFree,        viducRAM,      UFLAGS_RAMUPDATED,
    "$MUP",  vidcRAMUsedP,       viducRAM,      UFLAGS_RAMUPDATED,
    "$MU",   vidcRAMUsed,        viducRAM,      UFLAGS_RAMUPDATED,
    /* --------------------------------------------------------------------- */
    "$DFA",  vidcDiskFreeA,      viducDiskA,    UFLAGS_DISKA,
    "$DUA",  vidcDiskUsedA,      viducDiskA,    UFLAGS_DISKA,
    "$DTA",  vidcDiskTotalA,     viducDiskA,    UFLAGS_DISKA,
    "$DFB",  vidcDiskFreeB,      viducDiskB,    UFLAGS_DISKB,
    "$DUB",  vidcDiskUsedB,      viducDiskB,    UFLAGS_DISKB,
    "$DTB",  vidcDiskTotalB,     viducDiskB,    UFLAGS_DISKB,
    "$DFC",  vidcDiskFreeC,      viducDiskC,    UFLAGS_DISKC,
    "$DUC",  vidcDiskUsedC,      viducDiskC,    UFLAGS_DISKC,
    "$DTC",  vidcDiskTotalC,     viducDiskC,    UFLAGS_DISKC,
    "$DFD",  vidcDiskFreeD,      viducDiskD,    UFLAGS_DISKD,
    "$DUD",  vidcDiskUsedD,      viducDiskD,    UFLAGS_DISKD,
    "$DTD",  vidcDiskTotalD,     viducDiskD,    UFLAGS_DISKD,
    "$DFE",  vidcDiskFreeE,      viducDiskE,    UFLAGS_DISKE,
    "$DUE",  vidcDiskUsedE,      viducDiskE,    UFLAGS_DISKE,
    "$DTE",  vidcDiskTotalE,     viducDiskE,    UFLAGS_DISKE,
    "$DFF",  vidcDiskFreeF,      viducDiskF,    UFLAGS_DISKF,
    "$DUF",  vidcDiskUsedF,      viducDiskF,    UFLAGS_DISKF,
    "$DTF",  vidcDiskTotalF,     viducDiskF,    UFLAGS_DISKF,
    "$DFG",  vidcDiskFreeG,      viducDiskG,    UFLAGS_DISKG,
    "$DUG",  vidcDiskUsedG,      viducDiskG,    UFLAGS_DISKG,
    "$DTG",  vidcDiskTotalG,     viducDiskG,    UFLAGS_DISKG,
    "$DFH",  vidcDiskFreeH,      viducDiskH,    UFLAGS_DISKH,
    "$DUH",  vidcDiskUsedH,      viducDiskH,    UFLAGS_DISKH,
    "$DTH",  vidcDiskTotalH,     viducDiskH,    UFLAGS_DISKH,
    "$DFI",  vidcDiskFreeI,      viducDiskI,    UFLAGS_DISKI,
    "$DUI",  vidcDiskUsedI,      viducDiskI,    UFLAGS_DISKI,
    "$DTI",  vidcDiskTotalI,     viducDiskI,    UFLAGS_DISKI,
    "$DFJ",  vidcDiskFreeJ,      viducDiskJ,    UFLAGS_DISKJ,
    "$DUJ",  vidcDiskUsedJ,      viducDiskJ,    UFLAGS_DISKJ,
    "$DTJ",  vidcDiskTotalJ,     viducDiskJ,    UFLAGS_DISKJ,
    "$DFK",  vidcDiskFreeK,      viducDiskK,    UFLAGS_DISKK,
    "$DUK",  vidcDiskUsedK,      viducDiskK,    UFLAGS_DISKK,
    "$DTK",  vidcDiskTotalK,     viducDiskK,    UFLAGS_DISKK,
    "$DFL",  vidcDiskFreeL,      viducDiskL,    UFLAGS_DISKL,
    "$DUL",  vidcDiskUsedL,      viducDiskL,    UFLAGS_DISKL,
    "$DTL",  vidcDiskTotalL,     viducDiskL,    UFLAGS_DISKL,
    "$DFM",  vidcDiskFreeM,      viducDiskM,    UFLAGS_DISKM,
    "$DUM",  vidcDiskUsedM,      viducDiskM,    UFLAGS_DISKM,
    "$DTM",  vidcDiskTotalM,     viducDiskM,    UFLAGS_DISKM,
    "$DFN",  vidcDiskFreeN,      viducDiskN,    UFLAGS_DISKN,
    "$DUN",  vidcDiskUsedN,      viducDiskN,    UFLAGS_DISKN,
    "$DTN",  vidcDiskTotalN,     viducDiskN,    UFLAGS_DISKN,
    "$DFO",  vidcDiskFreeO,      viducDiskO,    UFLAGS_DISKO,
    "$DUO",  vidcDiskUsedO,      viducDiskO,    UFLAGS_DISKO,
    "$DTO",  vidcDiskTotalO,     viducDiskO,    UFLAGS_DISKO,
    "$DFP",  vidcDiskFreeP,      viducDiskP,    UFLAGS_DISKP,
    "$DUP",  vidcDiskUsedP,      viducDiskP,    UFLAGS_DISKP,
    "$DTP",  vidcDiskTotalP,     viducDiskP,    UFLAGS_DISKP,
    "$DFQ",  vidcDiskFreeQ,      viducDiskQ,    UFLAGS_DISKQ,
    "$DUQ",  vidcDiskUsedQ,      viducDiskQ,    UFLAGS_DISKQ,
    "$DTQ",  vidcDiskTotalQ,     viducDiskQ,    UFLAGS_DISKQ,
    "$DFR",  vidcDiskFreeR,      viducDiskR,    UFLAGS_DISKR,
    "$DUR",  vidcDiskUsedR,      viducDiskR,    UFLAGS_DISKR,
    "$DTR",  vidcDiskTotalR,     viducDiskR,    UFLAGS_DISKR,
    "$DFS",  vidcDiskFreeS,      viducDiskS,    UFLAGS_DISKS,
    "$DUS",  vidcDiskUsedS,      viducDiskS,    UFLAGS_DISKS,
    "$DTS",  vidcDiskTotalS,     viducDiskS,    UFLAGS_DISKS,
    "$DFT",  vidcDiskFreeT,      viducDiskT,    UFLAGS_DISKT,
    "$DUT",  vidcDiskUsedT,      viducDiskT,    UFLAGS_DISKT,
    "$DTT",  vidcDiskTotalT,     viducDiskT,    UFLAGS_DISKT,
    "$DFU",  vidcDiskFreeU,      viducDiskU,    UFLAGS_DISKU,
    "$DUU",  vidcDiskUsedU,      viducDiskU,    UFLAGS_DISKU,
    "$DTU",  vidcDiskTotalU,     viducDiskU,    UFLAGS_DISKU,
    "$DFV",  vidcDiskFreeV,      viducDiskV,    UFLAGS_DISKV,
    "$DUV",  vidcDiskUsedV,      viducDiskV,    UFLAGS_DISKV,
    "$DTV",  vidcDiskTotalV,     viducDiskV,    UFLAGS_DISKV,
    "$DFW",  vidcDiskFreeW,      viducDiskW,    UFLAGS_DISKW,
    "$DUW",  vidcDiskUsedW,      viducDiskW,    UFLAGS_DISKW,
    "$DTW",  vidcDiskTotalW,     viducDiskW,    UFLAGS_DISKW,
    "$DFX",  vidcDiskFreeX,      viducDiskX,    UFLAGS_DISKX,
    "$DUX",  vidcDiskUsedX,      viducDiskX,    UFLAGS_DISKX,
    "$DTX",  vidcDiskTotalX,     viducDiskX,    UFLAGS_DISKX,
    "$DFY",  vidcDiskFreeY,      viducDiskY,    UFLAGS_DISKY,
    "$DUY",  vidcDiskUsedY,      viducDiskY,    UFLAGS_DISKY,
    "$DTY",  vidcDiskTotalY,     viducDiskY,    UFLAGS_DISKY,
    "$DFZ",  vidcDiskFreeZ,      viducDiskZ,    UFLAGS_DISKZ,
    "$DUZ",  vidcDiskUsedZ,      viducDiskZ,    UFLAGS_DISKZ,
    "$DTZ",  vidcDiskTotalZ,     viducDiskZ,    UFLAGS_DISKZ,
    /* --------------------------------------------------------------------- */
    "$NCT",  vidcNetConnCount,   viducNetConn,  UFLAGS_NETCONN,
    "$NCC",  vidcNetCliCount,    viducNetConn,  UFLAGS_NETCONN,
    "$NCS",  vidcNetSrvCount,    viducNetConn,  UFLAGS_NETCONN,
    /* --------------------------------------------------------------------- */
    "$NTI0", vidcNetInTotal0,    viducNet,      UFLAGS_NETWORK,
    "$NTO0", vidcNetOutTotal0,   viducNet,      UFLAGS_NETWORK,
    "$NBI0", vidcNetInTraffic0,  viducNet,      UFLAGS_NETWORK,
    "$NBO0", vidcNetOutTraffic0, viducNet,      UFLAGS_NETWORK,
    "$NTI1", vidcNetInTotal1,    viducNet,      UFLAGS_NETWORK,
    "$NTO1", vidcNetOutTotal1,   viducNet,      UFLAGS_NETWORK,
    "$NBI1", vidcNetInTraffic1,  viducNet,      UFLAGS_NETWORK,
    "$NBO1", vidcNetOutTraffic1, viducNet,      UFLAGS_NETWORK,
    "$NTI2", vidcNetInTotal2,    viducNet,      UFLAGS_NETWORK,
    "$NTO2", vidcNetOutTotal2,   viducNet,      UFLAGS_NETWORK,
    "$NBI2", vidcNetInTraffic2,  viducNet,      UFLAGS_NETWORK,
    "$NBO2", vidcNetOutTraffic2, viducNet,      UFLAGS_NETWORK,
    "$NTI3", vidcNetInTotal3,    viducNet,      UFLAGS_NETWORK,
    "$NTO3", vidcNetOutTotal3,   viducNet,      UFLAGS_NETWORK,
    "$NBI3", vidcNetInTraffic3,  viducNet,      UFLAGS_NETWORK,
    "$NBO3", vidcNetOutTraffic3, viducNet,      UFLAGS_NETWORK,
    "$NTI4", vidcNetInTotal4,    viducNet,      UFLAGS_NETWORK,
    "$NTO4", vidcNetOutTotal4,   viducNet,      UFLAGS_NETWORK,
    "$NBI4", vidcNetInTraffic4,  viducNet,      UFLAGS_NETWORK,
    "$NBO4", vidcNetOutTraffic4, viducNet,      UFLAGS_NETWORK,
    "$NTI5", vidcNetInTotal5,    viducNet,      UFLAGS_NETWORK,
    "$NTO5", vidcNetOutTotal5,   viducNet,      UFLAGS_NETWORK,
    "$NBI5", vidcNetInTraffic5,  viducNet,      UFLAGS_NETWORK,
    "$NBO5", vidcNetOutTraffic5, viducNet,      UFLAGS_NETWORK,
    "$NTI6", vidcNetInTotal6,    viducNet,      UFLAGS_NETWORK,
    "$NTO6", vidcNetOutTotal6,   viducNet,      UFLAGS_NETWORK,
    "$NBI6", vidcNetInTraffic6,  viducNet,      UFLAGS_NETWORK,
    "$NBO6", vidcNetOutTraffic6, viducNet,      UFLAGS_NETWORK,
    "$NTI7", vidcNetInTotal7,    viducNet,      UFLAGS_NETWORK,
    "$NTO7", vidcNetOutTotal7,   viducNet,      UFLAGS_NETWORK,
    "$NBI7", vidcNetInTraffic7,  viducNet,      UFLAGS_NETWORK,
    "$NBO7", vidcNetOutTraffic7, viducNet,      UFLAGS_NETWORK,
    "$NTI8", vidcNetInTotal8,    viducNet,      UFLAGS_NETWORK,
    "$NTO8", vidcNetOutTotal8,   viducNet,      UFLAGS_NETWORK,
    "$NBI8", vidcNetInTraffic8,  viducNet,      UFLAGS_NETWORK,
    "$NBO8", vidcNetOutTraffic8, viducNet,      UFLAGS_NETWORK,
    "$NTI9", vidcNetInTotal9,    viducNet,      UFLAGS_NETWORK,
    "$NTO9", vidcNetOutTotal9,   viducNet,      UFLAGS_NETWORK,
    "$NBI9", vidcNetInTraffic9,  viducNet,      UFLAGS_NETWORK,
    "$NBO9", vidcNetOutTraffic9, viducNet,      UFLAGS_NETWORK,
    /* --------------------------------------------------------------------- */
    "$A",    vidcMerideumLong,   viducDateTime, UFLAGS_TMEUPDATED,
    "$a",    vidcMerideumShort,  viducDateTime, UFLAGS_TMEUPDATED,
    "$H",    vidcHour,           viducDateTime, UFLAGS_TMEUPDATED,
    "$h",    vidcLHour,          viducDateTime, UFLAGS_TMEUPDATED,
    "$I",    vidcMin,            viducDateTime, UFLAGS_TMEUPDATED,
    "$i",    vidcLMin,           viducDateTime, UFLAGS_TMEUPDATED,
    "$S",    vidcSecond,         viducDateTime, UFLAGS_TMEUPDATED,
    "$s",    vidcLSec,           viducDateTime, UFLAGS_TMEUPDATED,
    "$D",    vidcDay,            viducDateTime, UFLAGS_TMEUPDATED,
    "$d",    vidcLDay,           viducDateTime, UFLAGS_TMEUPDATED,
    "$M",    vidcMonth,          viducDateTime, UFLAGS_TMEUPDATED,
    "$m",    vidcLMonth,         viducDateTime, UFLAGS_TMEUPDATED,
    "$y",    vidcYear,           viducDateTime, UFLAGS_TMEUPDATED,
    "$Y",    vidcFYear,          viducDateTime, UFLAGS_TMEUPDATED,
    /* --------------------------------------------------------------------- */
    "",      NULL,               NULL,          UFLAGS_NONE
  };/* --------------------------------------------------------------------- */
  // For each identifier, add it to the list
  for(PVID vidDataPtr = (PVID)&vidData[0]; vidDataPtr->fpCallback; ++vidDataPtr)
    vidsData.push_back(*vidDataPtr);
  // OK
  return 0;
}
/* ========================================================================= */
const int Usage(bool bExtend)
{ // Show usage
  printf("Usage: siw [/opts] <*url|string> <file> [...].\n");
  // Done if not extended help
  if(!bExtend) return -1;
  // Show version
  printf("\nCopyright (c) MS-Design, 2016. All Rights Reserved."
         "\n%u-bit version compiled %s.\n", uiBits, cpTimestamp);
  // Create list of ids
  string strIds;
  for(VIDSI vidItem = vidsData.begin(); vidItem != vidsData.end(); ++vidItem)
    strIds += vidItem->strCommand + "\t";
  // Show extended help
  printf("\n%u identifiers supported:-\n%s\n", vidsData.size(), strIds.c_str());
  // Done
  return -1;
}
/* ========================================================================= */
inline const int InitCommandLineParameters(const int iArgC, const char **cpaArgV)
{ // No arguments?
  if(iArgC <= 1) return Usage(false);
  // Variable and file storage
  string strVar, strFile;
  // For each argument
  for(char **cpaArgVPtr = (char**)cpaArgV+1; *cpaArgVPtr != NULL; ++cpaArgVPtr)
  { // Is a switch character?
    if(**cpaArgVPtr == '/')
    { // Get option
      const uint8_t ucOpt = *(*cpaArgVPtr+1);
      // Bail if no option
      if(ucOpt <= 32)
      { // Show error
        printf("Warning: Used option-slash without suffix option name.\n");
        // Goto next parameter
        continue;
      }
      // Check parameter
      switch(ucOpt)
      { // Help
        case '?': return Usage(true);
        // Unknown option
        default: printf("Warning: Unknown option '/%c'!.\n", ucOpt); break;
      }
      // Goto next parameter
      continue;
    }
    // Not got variable?
    if(strVar.empty()) strVar = *cpaArgVPtr;
    // Not got file?
    else if(strFile.empty()) strFile = *cpaArgVPtr;
    // Compare lengths again
    if(!strVar.empty() && !strFile.empty())
    { // Insert command into map
      const CMD cmdData = { strVar, strFile };
      qCmds.push_back(cmdData);
      // Ready for a new command
      strVar.clear();
      strFile.clear();
    }
  }
  // Specified a string but no file for it?
  if(!strVar.empty() && strFile.empty())
  { // Show error
    printf("Missing value for '%s' argument.\n", strVar.c_str());
    // Bail
    return -1;
  }
  // No commands recorded?
  if(qCmds.empty())
  { // Show error
    printf("No commands specified.\n");
    // Bail
    return -2;
  }
  // Success
  return 0;
}
/* ========================================================================= */
inline const double QPC(void)
{ // Storage for performance counters
  static uint64_t qFreq, qCount;
  // Get frequency
  QueryPerformanceFrequency((PLARGE_INTEGER)&qFreq);
  // Get counter
  QueryPerformanceCounter((PLARGE_INTEGER)&qCount);
  // Return time
  return (double)qCount/(double)qFreq;
}
/* ========================================================================= */
inline const uint32_t HttpThread(const RUBLK ubData)
{ // Job started
  LD("Job started!");
  // Handles
  HINTERNET hConnect = NULL, hRequest = NULL;
  // Create file data
  FILE *fpStream = NULL;
  // Add to list
  EnterCriticalSection(&csHandle);
  ubBlocks[ubData.strURL] = ubData;
  LeaveCriticalSection(&csHandle);
  // Initialise function return value
  uint32_t ulReturn = 0;
  // For storing packets
  list<const PKT> lPackets;
  // Capture exceptions
  try
  { // Convert URL to wchar
    wstring wsTmp(ubData.strURL.begin(), ubData.strURL.end());
    // Initialise url components
    URL_COMPONENTS ucData = {
      sizeof(ucData),                  // dwStructSize
      NULL, (DWORD)-1, NULL,           // lpszScheme / dwSchemeLength / nScheme
      (LPWSTR)wsTmp.c_str(),           // lpszHostName
      (DWORD)ubData.strURL.length(),   // dwHostNameLength
      0,                               // nPort
      NULL, (DWORD)-1,                 // lpszUserName / dwUserNameLength
      NULL, (DWORD)-1,                 // lpszPassword / dwPasswordLength
      NULL, (DWORD)-1,                 // lpszUrlPath / dwUrlPathLength
      NULL, (DWORD)-1                  // lpszExtraInfo / dwExtraInfoLength
    };
    // Parse the URL
    LD("Parsing URL...");
    if(!WinHttpCrackUrl(wsTmp.c_str(), 0, 0, &ucData))
      throw string("Specified url '"+ubData.strURL+"' is invalid!");
    LD("Parsed URL successfully, results are...");
    LD("- Address...: %u:<%S>:%u [%u].", ucData.nScheme, ucData.lpszHostName,
      ucData.nPort, ucData.dwHostNameLength);
    LD("- User/Pass.: <%S>/<%S> [%u/%u].",
      ucData.dwUserNameLength ? ucData.lpszUserName : L"None",
      ucData.dwPasswordLength ? ucData.lpszPassword : L"None",
      ucData.dwUserNameLength, ucData.dwPasswordLength);
    LD("- Resource..: <%S> [%u].",
      ucData.dwUrlPathLength ? ucData.lpszUrlPath : L"Root",
      ucData.dwUrlPathLength);
    LD("- Parameters: <%S> [%u].",
      ucData.dwExtraInfoLength ? ucData.lpszExtraInfo : L"None",
      ucData.dwExtraInfoLength);

    // Do connect
    LN("Connecting to server...");
    hConnect = WinHttpConnect(hSession, wsTmp.c_str(), ucData.nPort, 0);
    if(!hConnect) throw string("WinHttpConnect("+ubData.strURL+") failed");
    LD("Connected, building request...");
    hRequest = WinHttpOpenRequest(hConnect, L"GET", ucData.lpszUrlPath,
      NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
      WINHTTP_FLAG_REFRESH);
    if(!hRequest) throw string("WinHttpOpenRequest("+ubData.strURL+") failed");
    LD("Request created, requesting resource, please wait...");
    if(!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
      WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        throw string("WinHttpSendRequest("+ubData.strURL+") failed");
    LD("Requested resource, waiting for reply...");

    // Get response
    if(!WinHttpReceiveResponse(hRequest, NULL))
      throw string("WinHttpReceiveResponse("+ubData.strURL+") failed");
    LD("Response received, processing last-modified time...");

    // For storing timestamp
    wchar_t wcaTime[32] = { 0 };
    // For storing size
    uint32_t ulSize = sizeof(wcaTime), ulRead;
    uint64_t qTotal = 0;
    // Build name of resource and hash it
    const string strRes = ubData.strOutFile+"|"+ubData.strURL;
    const uint64_t uqCRCvar = CRC64(0, (uint8_t*)strRes.c_str(), strRes.size());
    LD("Identifier: (0x%I64x) <%s>.", uqCRCvar, strRes.c_str());
    if(WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_LAST_MODIFIED,
      WINHTTP_HEADER_NAME_BY_INDEX, wcaTime, (LPDWORD)&ulSize,
      WINHTTP_NO_HEADER_INDEX))
    { // Get hash of value
      const uint64_t uqCRCval = CRC64(0, (uint8_t*)wcaTime, ulSize);
      LD("Value.....: (0x%I64x) <%S>.", uqCRCval, wcaTime);
      // find in list
      EnterCriticalSection(&csHandle2);
      const UMODLISTI umItem = umData.find(uqCRCvar);
      // Found it?
      if(umItem != umData.end())
      { // Resource modification time not changed? Forget doing anything more
        if(umItem->second == uqCRCval)
        { // Don't continue, close the connection and clean up
          LeaveCriticalSection(&csHandle2);
          LD("Refusing the download as last-modified time did not change.");
          throw (uint32_t)0;
        }
        // Update the time and play a sound
        umItem->second = uqCRCval;
        LeaveCriticalSection(&csHandle2);
        MessageBeep(MB_ICONINFORMATION);
        LD("Hash value updated in database.");
      } // Hash not initialised
      else
      { // Add the resource
        umData[uqCRCvar] = uqCRCval;
        LeaveCriticalSection(&csHandle2);
        LD("Hash of resource added to database.");
      }
    } // No more Last-Modified for some reason, delete our hash
    else
    { // Find original hash
      EnterCriticalSection(&csHandle2);
      const UMODLISTI umItem = umData.find(uqCRCvar);
      if(umItem != umData.end())
      { // Found it, so delete it
        umData.erase(umItem);
        LD("No more last-modified date, deleted hash.");
      }
      LeaveCriticalSection(&csHandle2);
    }
    // Loop forever
    for(;;)
    { // Get size
      if(!WinHttpQueryDataAvailable(hRequest, (LPDWORD)&ulSize))
        throw string("WinHttpQueryDataAvailable("+ubData.strURL+") failed");
      // No more data?
      if(!ulSize)
      { // We're done
        LD("Download completed because no more data.");
        break;
      }
      // Create packet data and allocate memory for it, then read into it
      LD("Allocating %u bytes and reading data into it...", ulSize);
      PKT pData = { (char*)malloc(ulSize), ulSize };
      if(!pData.cpPacket) throw string("malloc("+ubData.strURL+") failed");
      if(!WinHttpReadData(hRequest, (LPVOID)pData.cpPacket, (DWORD)ulSize,
        (LPDWORD)&ulRead))
          throw string("WinHttpReadData("+ubData.strURL+") failed");
      // No bytes read
      if(!ulRead)
      { // Free packet and try again
        free(pData.cpPacket);
        LD("Read zero bytes and ditched the packet, trying again...");
        continue;
      }
      // If not enough bytes read
      if(ulSize != ulRead)
      { // Resize packet to fit the new size
        pData.cpPacket = (char*)realloc(pData.cpPacket, ulRead);
        if(!pData.cpPacket) throw string("realloc("+ubData.strURL+") failed");
        pData.stSize = ulRead;
        LD("Packet resized to %u bytes.", ulRead);
      }
      else LD("Read %u of %u bytes into buffer.", ulSize, ulRead);
      // Add packet to list and increment the amount of bytes read
      lPackets.push_back(pData);
      qTotal += ulSize;
      LD("Read %u packets totalling %I64u bytes.", lPackets.size(), qTotal);
    }
    // No packets?
    if(lPackets.empty()) LD("No packets read, no write to file neccesary!");
    // Packets?
    else
    { // Create file, bail on error
      LD("Creating file '%s'...", ubData.strOutFile.c_str());
      if(fopen_s(&fpStream, ubData.strOutFile.c_str(), "wb"))
        throw string("fopen_s("+ubData.strOutFile+") failed!");
      LD("File created, writing packets...");
      // Until packets list is empty
      while(lPackets.begin() != lPackets.end())
      { // Get packet and write data to file, free and clear the packet
        RPKT pData = *lPackets.begin();
        if(fwrite(pData.cpPacket, pData.stSize, 1, fpStream) != 1)
          throw string("fputs("+ubData.strOutFile+") failed!");
        memset(pData.cpPacket, 0, pData.stSize);
        free(pData.cpPacket);
        pData.cpPacket = NULL;
        pData.stSize = 0;
        lPackets.pop_front();
      }
      // Close file
      LD("Wrote %u bytes to file!", ftell(fpStream));
      if(fclose(fpStream))
        throw string("fclose("+ubData.strOutFile+") failed!");
    }
    // Exit thread succeeded
    ulReturn = 0;
  } // A code was thrown
  catch(uint32_t ulCode)
  { // Normal exit
    ulReturn = ulCode;
  } // An error message was thrown
  catch(const string &strError)
  { // Show error
    printf("Thread Error: %s (errno=%u,gle).\n", strError.c_str(), errno);
    // Thread exit error status
    ulReturn = 1;
  }

  // Stream still open? (Might have got here because of throw
  if(fpStream)
  { // Try to close the file and reset it
    if(!fclose(fpStream)) LW("Could not close file stream handle!");
    fpStream = NULL;
  }
  // WinHTTP request handle open?
  if(hRequest)
  { // Close it
    if(!WinHttpCloseHandle(hRequest))
      LW("Could not close WinHTTP request handle!");
    else LD("WinHTTP request handle closed.");
  }
  // WinHTTP connection handle open?
  if(hConnect)
  { // Close it
    if(!WinHttpCloseHandle(hConnect))
      LW("Could not close WinHTTP connection handle!");
    else LD("WinHTTP connection handle closed.");
  }
  // Until packets list is empty
  while(lPackets.begin() != lPackets.end())
  { // Get packet
    RPKT pData = *lPackets.begin();
    // Packet allocated?
    if(pData.cpPacket)
    { // Clear and deallocate
      memset(pData.cpPacket, 0, pData.stSize);
      free(pData.cpPacket);
      pData.cpPacket = NULL;
    }
    if(pData.stSize) pData.stSize = 0;
    lPackets.pop_front();
  }

  // Suspend for requested time
  LD("Thread suspending for %g seconds...", (double)ubData.ulSleepTime / 1000);
  Sleep(ubData.ulSleepTime);
  // Remove me from URL processing list
  EnterCriticalSection(&csHandle);
  const UBLKSI ubItem = ubBlocks.find(ubData.strURL);
  if(ubItem != ubBlocks.end()) ubBlocks.erase(ubItem);
  LeaveCriticalSection(&csHandle);

  // Return status
  LN("Thread terminating with code %ul.", ulReturn);
  return ulReturn;
}
/* ========================================================================= */
inline const bool ShouldExit(void) { return (uqGFlags & GFLAGS_EXIT) != GFLAGS_NONE; }
/* ========================================================================= */
inline const int DoOperations(void)
{ // Return status
  int iReturn = 0;
  // File stream
  FILE *fpStream = NULL;
  // Initialise critical section
  InitializeCriticalSection(&csHandle);
  InitializeCriticalSection(&csHandle2);
  // Initialise size of memory struct
  memData.dwLength = sizeof(memData);
  // Assign http handle
  LD("Creating WinHTTP session...");
  hSession = WinHttpOpen(L"SIW/1.0",
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
    WINHTTP_NO_PROXY_BYPASS, 0);
  if(!hSession) throw string("WinHttpOpen() failed");
  else LN("WinHTTP session created!");
  // Capture exceptions
  try
  { // Update flags. Works as a sort of cache to check system stats once and
    // not do it again until the next loop.
    uint64_t uqFlags;
    // Initialise data values
    oData.precision(1);
    oData.flags(std::ios::fixed);
    // String to write
    string strOut;
    // Current and last position
    size_t stPos, stLPos;
    // Until exit requested
    for(;!ShouldExit();Sleep(1000))
    { // Clear update flags
      uqFlags = UFLAGS_NONE;
      // For each command
      for(CMDSI qItem = qCmds.begin(); qItem != qCmds.end(); ++qItem)
      { // Get item
        const RCMD cmdItem = *qItem;
        // Get command string
        const string &strCmd = cmdItem.strCmd;
        // Clear string
        strOut.clear();
        // Capture exceptions
        try
        { // Show progress
          LD("Processing command '%s'...", strCmd.c_str());
          // Compare initial token
          if(strCmd[0] == '*')
          { // Actual URL minus the asterisk
            const string strURL = strCmd.c_str()+1;
            // Show progress
            LD("Processing URL '%s'...", strURL.c_str());
            EnterCriticalSection(&csHandle);
            const UBLKSI ubItem = ubBlocks.find(strURL);
            LeaveCriticalSection(&csHandle);
            // Item not being requested?
            if(ubItem == ubBlocks.end())
            { // Assign name to output data to
              ubData.strOutFile = cmdItem.strFile;
              // Assign URL to download
              ubData.strURL = strURL;
              // Set sleep time
              ubData.ulSleepTime = 5000;
              // Show progress
              LD("Creating job to download '%s' to '%s'...", strURL.c_str(),
                cmdItem.strFile.c_str());
              // Create the thread
              if(!CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&HttpThread,
                (PVOID)&ubData, 0, NULL))
                  throw string("CreateThread failed!");
            } // Job ignored
            else LD("Job already in progress so ignoring for now.");
          }
          else
          { // Until end of command string
            for(stPos = strCmd.find('$'), stLPos = 0; stPos != string::npos;
              stLPos = stPos, stPos = strCmd.find('$', stLPos))
            { // Write unimportant data to output buffer
              strOut.append(strCmd.substr(stLPos, stPos-stLPos));
              // Iterator
              VIDSI vidIt;
              // Test each supported identifier against this command
              for(vidIt = vidsData.begin(); vidIt != vidsData.end(); ++vidIt)
              { // Get identifier struct
                const RVID vidItem = *vidIt;
                // Command matches one in argument?
                if(strCmd.substr(stPos, vidItem.strCommand.length()) ==
                   vidItem.strCommand)
                { // Check if data needs updating, update and indicate if failed
                  if(vidItem.fpUCallback && !(uqFlags & vidItem.uqFlag) &&
                     vidItem.fpUCallback() == false)
                    strOut.append("<!"+vidItem.strCommand+"!>");
                  else
                  { // Else grab the data and write it to the output string
                    strOut.append(vidItem.fpCallback());
                    // Add flag so it doesnt update again on this iteration
                    uqFlags |= vidItem.uqFlag;
                  }
                  // Skip ahead
                  stPos += vidItem.strCommand.length();
                  // Done
                  break;
                }
              }
              // No identifier found so throw warning out there
              if(vidIt == vidsData.end())
                throw string("Unmatched identifier in '"+strCmd+"'!");
            }
            // Still unwritten characters? Write the rest
            if(stLPos != stPos) strOut.append(strCmd.substr(stLPos));
            // Create file, bail on error
            if(fopen_s(&fpStream, cmdItem.strFile.c_str(), "wb"))
              throw string("fopen_s("+cmdItem.strFile+") failed!");
            // Write string to file
            if(fputs(strOut.c_str(), fpStream))
              throw string("fputs("+strOut+","+cmdItem.strFile+") failed!");
            // Close file
            if(fclose(fpStream))
              throw string("fclose("+cmdItem.strFile+") failed!");
          }
        } // Error string thrown
        catch(const string &strError) { LW("%s", strError.c_str()); }
        // Close file if opened
        if(fpStream) fclose(fpStream);
        // Done with stream
        fpStream = NULL;
      }
    }
  } // Error thrown
  catch(const string &strError)
  { // Show error
    LE("Fatal: %s.", strError.c_str());
    // Return error status;
    iReturn = -1;
  }
  // WinHTTP session opened?
  if(hSession)
  { // Close it
    LD("Closing WinHTTP session...");
    if(WinHttpCloseHandle(hSession))
      LN("WinHTTP session successfully closed!");
    else LW("Failed to close WinHTTP session!");
  }
  // DeInitialise critical sections
  DeleteCriticalSection(&csHandle2);
  DeleteCriticalSection(&csHandle);
  // Returning status
  LD("Returning status code %d...", iReturn);
  // Return status
  return iReturn;
}
/* ========================================================================= */
inline void Terminate(void)
{ // Ignore if operations not started
  if(!ShouldExit()) return;
  // Log termination message
  LN("Program terminated!");
}
/* ========================================================================= */
inline BOOL Signal(unsigned long ulType)
{ // Termination message
  char *cpMessage;
  // Which event
  switch(ulType)
  { // Handle the CTRL+C signal.
    case CTRL_C_EVENT: cpMessage = "Control+C"; break;
    // CTRL+CLOSE: confirm that the user wants to exit.
    case CTRL_CLOSE_EVENT: cpMessage = "Control+Close"; break;
    // CTRL+BREAK pressed.
    case CTRL_BREAK_EVENT: cpMessage = "Control+Break"; break;
    // Logging off.
    case CTRL_LOGOFF_EVENT: cpMessage = "Logoff"; break;
    // Shutting down.
    case CTRL_SHUTDOWN_EVENT: cpMessage = "Shutdown"; break;
    // No message
    default: cpMessage = NULL; break;
  }
  // No message? Not handled!
  if(!cpMessage) return FALSE;
  // Already terminating
  if(ShouldExit()) LW("%s signalled, already terminating!", cpMessage);
  // First termination
  else
  { // Say in log
    LW("%s signalled, terminating...", cpMessage);
    // Program should exit
    uqGFlags |= GFLAGS_EXIT;
  }
  // Handled
  return TRUE;
}
/* ========================================================================= */
const int main(const int iArgC, const char **cpaArgV) try
{ // No windows errors!
  SetErrorMode(0xFFFFFFFF);
  // Do stuff at exit
  atexit(Terminate);
  // Compile indentifiers list
  if(InitIdentifiers() < 0) return 3;
  // Compile command line parameters
  if(InitCommandLineParameters(iArgC, cpaArgV) < 0) return 2;
  // Program starting
  uqGFlags |= GFLAGS_STARTED;
  // Capture control and C
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)Signal, TRUE);
  // Show version
  LN("Starting System Information Writer compiled %s.", cpTimestamp);
  // Show what we did
  LD("Compiled %u identifiers!", vidsData.size());
  LD("Compiled %u command-line parameters!", iArgC);
  LN("Compiled %u procedures!", qCmds.size());
  // Do operations
  LD("Now performing operations...");
  if(DoOperations() < 0) return 4;
  LN("Finished peforming operations, terminating!");
  // Done
  return 0;
} // Caught c++ exception
catch(const exception &e)
{ // Print error
  LE("Caught exception '%s', terminating!", e.what());
  // Error
  return 5;
}
/* ========================================================================= */
