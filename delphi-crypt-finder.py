import ida_bytes
import ida_name
import idautils
import idc

insn_pattern = [0xf, 0x33, 0x89, 0x8b, 0x3b]

reg_location = [0, 0, 1, 0, 0]

def search_crypt_insns(x):
    h = x
    register = idc.print_operand(x, 0)
    for i in range(len(insn_pattern)):
        if not ida_bytes.get_byte(h) == insn_pattern[i]:
            return 0
        if not register == idc.print_operand(h, reg_location[i]):
            return 0
        h = next_head(h)
    return 1
             
def search_crypto_init():
    for function in idautils.Functions():
        flags = idc.get_func_attr(function, FUNCATTR_FLAGS)
        if flags & FUNC_LIB or flags & FUNC_THUNK or flags & 65536: #FUNC_LUMINA
            continue
        for x in idautils.FuncItems(function):
            if search_crypt_insns(x) == 1:
                print("Crypto function found at: %X" % function)
                ida_name.force_name(function, "mw_string_decrypt")
            continue         
            
search_crypto_init()
print("Analysis finished")
