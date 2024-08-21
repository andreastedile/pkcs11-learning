from aalpy import MealyMachine

from alphabet import INPUT_ALPHABET


def convert_automaton_to_smv_model(automaton: MealyMachine, file: str):
    with open(file, "w") as f:
        f.write("MODULE main\n")

        f.write("  VAR\n")

        state_ids = [state.state_id for state in automaton.states]
        comma_separated_state_ids = ", ".join(state_ids)
        f.write(f"  state : {{{comma_separated_state_ids}}};\n")

        comma_separated_inputs = ", ".join(INPUT_ALPHABET)
        f.write(f"  inp : {{{comma_separated_inputs}}};\n")

        f.write("  out : {ok, fail, inapplicable};\n")

        f.write("  ASSIGN\n")

        f.write("  init(state) := s0;\n")

        f.write("  next(state) := case\n")
        for source in automaton.states:
            for label, destination in source.transitions.items():
                f.write(f"    state = {source.state_id} & inp = {label}: {destination.state_id};\n")
        f.write("  esac;\n")

        f.write("  out:= case\n")
        for source in automaton.states:
            for label in source.transitions.keys():
                out = source.output_fun[label]
                f.write(f"    state = {source.state_id} & inp = {label}: {out};\n")
        f.write("  esac;\n\n")


def append_ltl_properties_to_file(file: str):
    with open(file, "a") as f:
        f.write("LTLSPEC\n  G(inp = C_Decrypt_wrapped0 -> (out = fail | out = inapplicable))")
