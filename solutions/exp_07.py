import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output


proj = angr.Project('./07_angr_symbolic_file',auto_load_libs=False)

file = "NKQJZUPT.txt"
symbolic_file_size = 64

#after the scan
start_addr = 0x08049564 #we place ourselves before we open the file descriptor
initial_state = proj.factory.blank_state(
    addr=start_addr,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )


#defining the inputs
inp_1 = claripy.BVS('content', symbolic_file_size*8)

password_file = angr.storage.SimFile(file, content=inp_1)

initial_state.fs.insert(file, password_file)


pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]
    
    #solving for a string
    sol_1 = s.solver.eval(inp_1, cast_to=bytes).decode()
    sol_unc = sol_1
    print(sol_unc)
else:
    raise Exception("No solution")


