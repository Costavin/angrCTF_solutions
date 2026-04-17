import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output


proj = angr.Project('./06_angr_symbolic_dynamic_memory',auto_load_libs=False)

#after the scan
start_addr= 0x0804938c
initial_state = proj.factory.blank_state(
    addr=start_addr,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

initial_state.regs.ebp = initial_state.regs.esp

#defining the inputs
inp_1 = claripy.BVS('pass_1', 8*8)
inp_2 = claripy.BVS('pass_2', 8*8)

fake_heap_add_1 = 0x0804c042  
pointer_to_malloc_memory_add_1 = 0x0a78373c #buffer_1

fake_heap_add_2 = 0x0804c052 
pointer_to_malloc_memory_add_2 = 0x0a783744 #buffer_2

initial_state.memory.store(pointer_to_malloc_memory_add_1, fake_heap_add_1, endness=proj.arch.memory_endness)
initial_state.memory.store(pointer_to_malloc_memory_add_2, fake_heap_add_2, endness=proj.arch.memory_endness)

initial_state.memory.store(fake_heap_add_1, inp_1)
initial_state.memory.store(fake_heap_add_2, inp_2)

pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]
    
    #solving for a string
    sol_1 = s.solver.eval(inp_1, cast_to=bytes).decode()
    sol_2 = s.solver.eval(inp_2, cast_to=bytes).decode()
    sol_unc = sol_1 + sol_2
    print(sol_unc)
else:
    raise Exception("No solution")


