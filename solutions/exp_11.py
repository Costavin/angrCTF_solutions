import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output

proj = angr.Project('./11_angr_sim_scanf')#,auto_load_libs=False)

initial_state = proj.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

#hooking all check equals functions
class ReplacementScanf(angr.SimProcedure):
    def run(self, string, buffer_1_adr, buffer_2_adr):
        buffer_1 = claripy.BVS("buf_1", 4*8)
        buffer_2 = claripy.BVS("buf_2", 4*8)
        self.state.memory.store(
            buffer_1_adr, buffer_1,
            endness=proj.arch.memory_endness
        )
        self.state.memory.store(
            buffer_2_adr, buffer_2,
            endness=proj.arch.memory_endness
        )
        self.state.globals['solution1'] = buffer_1
        self.state.globals['solution2'] = buffer_2


scan_symbol = "__isoc99_scanf"   #function name
proj.hook_symbol(scan_symbol, ReplacementScanf())

       
pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]
    stored_sol1 = s.globals['solution1']
    stored_sol2 = s.globals['solution2']
    sol_1 = s.solver.eval(stored_sol1)
    sol_2 = s.solver.eval(stored_sol2)
    print(str(sol_1) + " " + str(sol_2))
else:
    raise Exception("No solution")


