import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output



proj = angr.Project('./09_angr_hooks')#,auto_load_libs=False)


initial_state = proj.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

check_equals_called_addr = 0x080493ce   #check_equals function to hook
instruction_to_skip_length = 5          #how many bytes to skip - 5 bytes instr

@proj.hook(check_equals_called_addr, length=instruction_to_skip_length)
def skip_check_equals_(state):
    user_input_buffer_address = 0x0804c044
    user_input_buffer_length = 16       #in bytes, not bits
    user_input_string = state.memory.load(
        user_input_buffer_address,
        user_input_buffer_length
    )
    check_against_string = "LRGTVUUMRBUJTFPF".encode('utf-8')
    state.regs.eax = claripy.If(
        user_input_string == check_against_string,
        claripy.BVV(1, 32),
        claripy.BVV(0, 32)
    )

pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]
    
    #angr manages the input
    print("Flag: " + s.posix.dumps(sys.stdin.fileno()).decode() )
else:
    raise Exception("No solution")


