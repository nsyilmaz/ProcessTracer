
SYS_open:
addr = ebx
size = STR_MAX
return = eax
umovestr_peekdata
-------------------------------------
SYS_close:
return = eax
param = ebx
-------------------------------------

SYS_read:
addr = ecx
size = eax
return = eax
umoven_peekdata
-------------------------------------

SYS_write:
addr = ecx
size = eax
return = eax
umoven_peekdata
-------------------------------------

SYS_send:
addr = ecx
size = eax
get_args
getdata
-------------------------------------

SYS_recv:
addr = ecx
size = eax
get_args
getdata
-------------------------------------







