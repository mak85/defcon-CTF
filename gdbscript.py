"""GDB script: break at FUN_001011a0, dump R12 array, and observe RAX on return."""
import gdb

# Compute the load address — find main object's base
def get_base():
    info = gdb.execute('info proc mappings', to_string=True)
    # Find the first executable mapping that points to our binary
    for line in info.splitlines():
        if 'myfavoriteinstructions' in line:
            parts = line.split()
            return int(parts[0], 16)
    return 0

gdb.execute('set pagination off')
gdb.execute('set confirm off')

# Run to entry, then set breakpoint at validator
gdb.execute('starti AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
base = get_base()
print(f'[+] base = {hex(base)}')

# Validator offset in file: 0x11a0
validator_addr = base + 0x11a0
print(f'[+] validator @ {hex(validator_addr)}')
gdb.execute(f'break *{hex(validator_addr)}')
gdb.execute('continue')

# At validator entry. Read R12 and dump the array.
r12 = int(gdb.parse_and_eval('$r12'))
print(f'[+] R12 = {hex(r12)}')

print('[+] Array contents (200 u64 entries):')
data = gdb.selected_inferior().read_memory(r12, 200 * 8)
import struct
vals = list(struct.unpack('<200Q', data))
print('vals =', vals)

# Continue to function return, then check RAX
# Break at validator end (offset 0x4d985 = end of function)
ret_addr = base + 0x4d985
gdb.execute(f'break *{hex(ret_addr)}')
gdb.execute('continue')

rax = int(gdb.parse_and_eval('$rax')) & 0xffffffff
print(f'[+] RAX on return = {rax}')

gdb.execute('quit')
