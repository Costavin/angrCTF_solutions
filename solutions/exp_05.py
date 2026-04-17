import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output


proj = angr.Project('./05_angr_symbolic_memory',auto_load_libs=False)

#after the scan
start_addr = 0x08049315
initial_state = proj.factory.blank_state(
    addr=start_addr,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

initial_state.regs.ebp = initial_state.regs.esp

#defining the inputs
inp_1 = claripy.BVS('pass_1', 8*8)
inp_2 = claripy.BVS('pass_2', 8*8)
inp_3 = claripy.BVS('pass_3', 8*8)
inp_4 = claripy.BVS('pass_4', 8*8)

add_1 = 0x9111260
add_2 = 0x9111268
add_3 = 0x9111270 
add_4 = 0x9111278

initial_state.memory.store(add_1, inp_1)
initial_state.memory.store(add_2, inp_2)
initial_state.memory.store(add_3, inp_3)
initial_state.memory.store(add_4, inp_4)


pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]
    
    #solving for a string
    sol_1 = s.solver.eval(inp_1, cast_to=bytes).decode()
    sol_2 = s.solver.eval(inp_2, cast_to=bytes).decode()
    sol_3 = s.solver.eval(inp_3, cast_to=bytes).decode()
    sol_4 = s.solver.eval(inp_4, cast_to=bytes).decode()
    sol_unc = sol_1 + sol_2 + sol_3 + sol_4
    print(sol_unc)
else:
    raise Exception("No solution")


