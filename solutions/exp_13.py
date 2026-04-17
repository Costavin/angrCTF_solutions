import angr
import sys
import claripy

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Good Job' in stdout_output

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Try Again.' in stdout_output

proj = angr.Project('./13_angr_static_binary',auto_load_libs=False)

starting_addr = 0x08049e0f
initial_state = proj.factory.blank_state(
    addr=starting_addr,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )


proj.hook(0x080512f0, angr.SIM_PROCEDURES['libc']['printf']())
proj.hook(0x0805eca0, angr.SIM_PROCEDURES['libc']['puts']())
proj.hook(0x08051340, angr.SIM_PROCEDURES['libc']['scanf']())
proj.hook(0x0804a240, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

pg = proj.factory.simgr(initial_state, veritesting=True)
pg.explore(find = is_succ, avoid = should_abort)


print("End exploration")
if pg.found:
    s = pg.found[0]

    #angr manages the input
    print("Flag: " + s.posix.dumps(sys.stdin.fileno()).decode() )
else:
    raise Exception("No solution")


