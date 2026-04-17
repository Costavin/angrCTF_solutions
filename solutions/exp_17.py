import angr
import claripy
import sys

def main():
    path = "./17_angr_arbitrary_jump"
    project = angr.Project(path, auto_load_libs=False)#, use_sim_procedures=False)
    input_len = 100
    #symbolic_input =  claripy.BVS("input", 8*input_len)
    #stdin_=angr.SimFileStream(name='stdin', content=symbolic_input, has_end=False) 
    initial_state = project.factory.entry_state(
            add_options={
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
                }
            )

    simulation = project.factory.simgr(
            initial_state,
            save_unconstrained=True,
            stashes={
                'active' : [ initial_state ],
                'unconstrained' : [],
                'found' : [],
                'not_needed' : []
                }
            )

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, buffer_0):
            scanf0 = claripy.BVS('scanf0', 8*input_len)
            for char in scanf0.chop(bits=8):
                self.state.add_constraints(char >= 33, char <= 126)
            scanf0_address = buffer_0
            self.state.memory.store(scanf0_address, scanf0,
                                    endness=project.arch.memory_endness)
            self.state.memory.store(scanf0_address, scanf0)
            self.state.globals['solution0'] = scanf0

    scanf_symbol = "__isoc99_scanf"
    project.hook_symbol(scanf_symbol, ReplacementScanf())


    def has_found_solution():
        return simulation.found

    def has_unconstrained_to_check():
        return simulation.unconstrained

    def has_active():
        return simulation.active


    while (has_active() or has_unconstrained_to_check()) and (not has_found_solution()):
        for unconstrained_state in simulation.unconstrained:
            simulation.move(from_stash='unconstrained', to_stash='found') 
        if not has_found_solution():
            simulation.step()

    print(simulation)


    if simulation.found:
        solution_state = simulation.found[0]
        solution_state.add_constraints(solution_state.regs.eip == 0x46434558) #1178813784)

        #for byte in scanf0.chop(bits=8):
         #   solution_state.add_constraints(
         #       byte >= 'A'.encode('utf-8'),
         #       byte <= 'Z'.encode('utf-8')
         #   )

        # Solve for the symbolic_input
        solution = solution_state.solver.eval(solution_state.globals['solution0'], cast_to=bytes).decode()
        print(solution)
    else:
        raise Exception('Could not find the solution')


main()
