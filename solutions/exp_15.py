import angr
import claripy
import sys

def main():
    path_to_binary = "./15_angr_arbitrary_read"
    project = angr.Project(path_to_binary, auto_load_libs=False)

    initial_state = project.factory.entry_state(
        add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                       angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
        )

    class ReplacementScanf(angr.SimProcedure):
        #gets automatically the targets of scanf
        def run(self, format_string, buffer_0, buffer_1):
            # %u
            scanf0 = claripy.BVS('scanf0_key', 8*4) #integer
            # %20s
            scanf1 = claripy.BVS('scanf1', 8*20)    #string
            # we can write 20 characters, and overwrite the variable defined above it

            #add constraints over the 16 chars + 4 chars
            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 0x21, char <= 0x7e)
                #self.state.add_constraints(char >= 33, char <= 126)
                #self.state.add_constraints(char >= 'A'.encode(), char <= 'Z'.encode())

            self.state.memory.store(buffer_0, scanf0,
                                    endness=project.arch.memory_endness)
            self.state.memory.store(buffer_1, scanf1)
            #put aside
            self.state.globals['solution0'] = scanf0
            self.state.globals['solution1'] = scanf1


    #hook the scanf with our version
    scanf_symbol = "__isoc99_scanf"
    project.hook_symbol(scanf_symbol, ReplacementScanf())

    def check_puts(state):
         #get the the argument from put, from the stack, with respect to esp
        puts_parameter = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
        if state.solver.symbolic(puts_parameter):
            good_job_string_address = 0x434a4a57
            is_vulnerable_expression = (puts_parameter == good_job_string_address)
            #doesnt work, z3 cant convert to boolean value
            #is_vulnerable_expression = claripy.If(puts_parameter == good_job_string_address,
                                        #claripy.BVV(1,1), claripy.BVV(0,1) ) # :boolean bitvector expression
            if state.satisfiable(extra_constraints=(is_vulnerable_expression,)):
                state.add_constraints(is_vulnerable_expression)
                return True
            else:
                return False
        else: # not state.solver.symbolic(???)
            return False

    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        puts_address = 0x08049090          #call to the thunk function
        if state.addr == puts_address:
            return check_puts(state)
        else:
            return False

    simulation.explore(find=is_successful)

    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.solver.eval(solution_state.globals['solution0'])
        sol_2 =  solution_state.solver.eval(solution_state.globals['solution1'],cast_to=bytes).decode()
        print(str(solution) + " " + sol_2)
    else:
        raise Exception('Could not find the solution')



main()
    


