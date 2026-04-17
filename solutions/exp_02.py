import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output


proj = angr.Project('./02_angr_find_condition',auto_load_libs=False)

initial_state = proj.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

pg = proj.factory.simgr(initial_state)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]
    print("Flag: " + s.posix.dumps(sys.stdin.fileno()).decode() )
else:
    raise Exception("No solution")


