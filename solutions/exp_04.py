import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output


proj = angr.Project('./04_angr_symbolic_stack',auto_load_libs=False)

#2 address after scanf (skip the add to esp)
start_addr = 0x080493f2
initial_state = proj.factory.blank_state(
    addr=start_addr,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

initial_state.regs.ebp = initial_state.regs.esp

#defining the inputs
inp_1 = claripy.BVS('pass_1', 1*4*8)    #undef4 is 4 bytes
inp_2 = claripy.BVS('pass_2', 1*4*8)

#shift 8 bytes in the stack / 0x10 - aling to first argument
padding_length_in_bytes = 8
initial_state.regs.esp -= padding_length_in_bytes


initial_state.stack_push(inp_1)
initial_state.stack_push(inp_2)


pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]

    sol_1 = s.solver.eval(inp_1)
    sol_2 = s.solver.eval(inp_2)
    sol_unc = str(sol_1) + " " + str(sol_2)
    print(sol_unc)
    sol = hex(sol_1)[2:] + " " + hex(sol_2)[2:]
    print(sol)
else:
    raise Exception("No solution")


