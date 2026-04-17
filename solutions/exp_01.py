import angr
import sys
import claripy

proj = angr.Project('./01_angr_avoid',auto_load_libs=False)

initial_state = proj.factory.entry_state(
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

pg = proj.factory.simgr(initial_state)
addr_tgt = 0x08049300
addr_to_avoid = [ 0x080492bb]
pg.explore(find = addr_tgt, avoid = addr_to_avoid)


print("End exploration")
if pg.found:
    s = pg.found[0]
    print("Flag: " + s.posix.dumps(sys.stdin.fileno()).decode() )
else:
    raise Exception("No solution")


