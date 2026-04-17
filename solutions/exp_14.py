import angr
import sys
import claripy

def main():
    path_bin = "./lib14_angr_shared_library.so"
    base = 0x00010000
    project = angr.Project(path_bin, load_options={
        'main_opts' : {
            'base_addr' : base
        }
    })

    buffer_pointer_1 = claripy.BVV(0x80000000, 8*4)

    validate_function_address = base + 0x0000129c
    initial_state = project.factory.call_state(
                    validate_function_address,
                    buffer_pointer_1,
                    claripy.BVV(0x8,8*4),   #length = 8, written in a 8*4 struct (int)
                    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
                  )

    password = claripy.BVS( "pass_prog", 8*8 )
    initial_state.memory.store(buffer_pointer_1, password)


    pg = project.factory.simgr(initial_state)

    check_constraint_address = base + 0x00001348    #just at the end, in order to match if it returns true or false. Not where it passes the arguments to strncmp through eax.
    pg.explore(find=check_constraint_address)

    print("End exploration")
    if pg.found:
        s = pg.found[0]
        s.add_constraints(  s.regs.eax != 0 )
        solution = s.solver.eval(password, cast_to=bytes).decode()
        print(solution)
    else:
        raise Exception("No solution")

main()

