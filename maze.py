
import angr
import claripy
import sys

def is_succ(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Correct!' in stdout_output

def wall(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Wall' in stdout_output

def missing(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Missing' in stdout_output

def no_exit(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Did not' in stdout_output

def invalid(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'Invalid' in stdout_output

def no_in(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'No input' in stdout_output


def main():
    path_to_binary = "/home/costantino/Downloads/ctf/reverse/maze/maze_runner"
    project = angr.Project(path_to_binary, auto_load_libs=False)
    #symbolic_input = claripy.BVS("input",0x20*8)


    initial_state = project.factory.entry_state(
            add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
        )

    simulation = project.factory.simgr(initial_state)

    simulation.explore(find=is_succ, avoid=[wall, missing, no_exit, invalid, no_in])

    if simulation.found:
        #solution_state = simulation.found[0]
        #solution = solution_state.solver.eval(solution_state.gloabals['solution0'], cast_to=bytes)
        print("Flag: " + s.posix.dumps(sys.stdin.fileno()).decode() )

        #print(solution)
    else:
        raise Exception('Could not find the solution')



main()
    


