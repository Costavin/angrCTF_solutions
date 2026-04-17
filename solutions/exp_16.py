import angr
import claripy
import sys

def main():
    path_bin = "./16_angr_arbitrary_write"
    project = angr.Project(path_bin, auto_load_libs=False)

    initial_state = project.factory.entry_state(
            add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
            )
    
    class ReplacementScanf(angr.SimProcedure):
        # Hint: scanf("%u %20s")
        def run(self, format_string, buffer_0, buffer_1):
            scanf0 = claripy.BVS('scanf0', 8*4)
            scanf1 = claripy.BVS('scanf1', 8*20)
            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 33, char <= 126)
            scanf0_address = buffer_0
            self.state.memory.store(scanf0_address, scanf0,
                                    endness=project.arch.memory_endness)
            scanf1_address = buffer_1
            self.state.memory.store(scanf1_address, scanf1)
            self.state.globals['solution0'] = scanf0
            self.state.globals['solution1'] = scanf1

    scanf_symbol = "__isoc99_scanf"
    project.hook_symbol(scanf_symbol, ReplacementScanf())

    def check_strncpy(state):
        #they are all integers
        strncpy_dest = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
        strncpy_src = state.memory.load(state.regs.esp + 8, 4, endness=project.arch.memory_endness)
        strncpy_len = state.memory.load(state.regs.esp + 12, 4, endness=project.arch.memory_endness)
        #src_contents = state.memory.load(strncpy_src,strncpy_len)
        src_contents = state.memory.load(strncpy_src, 16)
        #dst_contents = state.memory.load(strncpy_dest, 4)

        if state.solver.symbolic(src_contents) and state.solver.symbolic(strncpy_dest):
            password_string = b"RFWOKZXV"
            buffer_address = 0x4d4b5148
            does_src_hold_password = src_contents[-1:-8*8] == password_string
            does_dest_equal_buffer_address = strncpy_dest  == buffer_address
            if state.satisfiable(extra_constraints=(does_src_hold_password, does_dest_equal_buffer_address)):
                state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
                return True
            else:
                return False
        else: # not state.solver.symbolic(???)
            return False

    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        strncpy_address = 0x080490f0         #thunk
        if state.addr == strncpy_address:
            return check_strncpy(state)
        else:
            return False

    simulation.explore(find=is_successful)
    
    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.solver.eval(solution_state.globals['solution0'])
        sol_1 =  solution_state.solver.eval(solution_state.globals['solution1'],cast_to=bytes).decode()
        print(str(solution) + " " + sol_1)
    else:
        raise Exception('Could not find the solution')

main()








