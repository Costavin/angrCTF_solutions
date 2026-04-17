import angr
import sys
import claripy

proj = angr.Project('./08_angr_constraints',auto_load_libs=False)


#after the scan
start_addr = 0x0804935d  
#0x080493a9     #before cmp fun call - it doesnt work, as the buffer doesnt get modified
#0x0804935d     #after the scan input and pass decl, before buffer modification
initial_state = proj.factory.blank_state(
    addr=start_addr,
    add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )

#defining the inputs
#fill the password buffer with our vector BVS
inp_1 = claripy.BVS('password', 16*8)
pass_str = "RKKMOOUVQGJOZEQJ"
pass_addr = 0x0804c040  #buffer

initial_state.memory.store(pass_addr, inp_1)    #load the bvs to buffer

addr_to_check_constraint =  0x080493ae  #call cmp func   #0x080492c8 #in function cmp

pg = proj.factory.simgr(initial_state)
pg.explore(find = addr_to_check_constraint)


print("End exploration")
if pg.found:
    s = pg.found[0]

    constrained_parameter_address = 0x0804c040  #buffer
    constrained_parameter_size_bytes = 16       #16 bytes in it
    constrained_parameter_bitvector = s.memory.load(
      constrained_parameter_address,
      constrained_parameter_size_bytes
    )
    constrained_parameter_desired_value = pass_str.encode('utf-8') # :string (encoded)
    s.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)
   
    sol_1 = s.solver.eval(inp_1, cast_to=bytes).decode()

    print(sol_1)
else:
    raise Exception("No solution")


