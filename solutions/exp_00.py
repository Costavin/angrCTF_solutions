import angr
import sys
import claripy

proj = angr.Project('./00_angr_find',auto_load_libs=False)

initial_state = proj.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

pg = proj.factory.simgr(initial_state)
pg.explore(find=(0x080492f8))


print("end exploration")
if pg.found:
    s = pg.found[0]
    print("Flag: ", s.posix.dumps(0)) #s.posix.dumps(sys.stdin.fileno()).decode()
else:
    raise Exception("No solution")


