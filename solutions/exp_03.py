import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output


proj = angr.Project('./03_angr_symbolic_registers',auto_load_libs=False)
#entry_state doesnt need an entry state, as it starts from the start
#Start_address when we want to specify a random start - note we need a blank state
start_addr = 0x0804956a
initial_state = proj.factory.blank_state(
    addr=start_addr,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

inp_1 = claripy.BVS('pass_1', 4*8)
initial_state.regs.eax=inp_1

inp_2 = claripy.BVS('pass_2', 4*8)
initial_state.regs.ebx=inp_2

inp_3 = claripy.BVS('pass_3', 4*8)
initial_state.regs.edx=inp_3

pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]

    sol_1 = s.solver.eval(inp_1)
    sol_2 = s.solver.eval(inp_2)
    sol_3 = s.solver.eval(inp_3)
    sol = hex(sol_1)[2:] + " " + hex(sol_2)[2:] + " " + hex(sol_3)[2:]
    print(sol)
else:
    raise Exception("No sol")


