import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output

proj = angr.Project('./10_angr_simprocedures')#,auto_load_libs=False)

initial_state = proj.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

#hooking all check equals functions
class ReplacementCheckEquals(angr.SimProcedure):
    def run(self, to_check, size):
        user_input_buffer_address = to_check
        user_input_buffer_length = size       #no need to define
        user_input_string = self.state.memory.load(
            user_input_buffer_address,
            user_input_buffer_length
        )
        check_against_string = "FTURSWJQLRBHBOOE".encode('utf-8')
        return claripy.If(
            user_input_string == check_against_string,
            claripy.BVV(1, 32),
            claripy.BVV(0, 32)
        )

#check_equals_symbol = "check_equals_FTURSWJQLRBHBOOE"   #function name
#proj.hook_symbol(check_equals_symbol, ReplacementCheckEquals())
check_eq_addr = 0x080492d8                              #first addr of check_eq...
proj.hook(check_eq_addr,ReplacementCheckEquals())
       
pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]
    
    #angr manages the input
    print("Flag: " + s.posix.dumps(sys.stdin.fileno()).decode() )
else:
    raise Exception("No solution")


