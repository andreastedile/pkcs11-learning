from aalpy import MealyState, Automaton

from abstract_pkcs11_commands import NOT_APPLICABLE


def remove_not_applicable_transitions(mealy: Automaton) -> Automaton:
    """
    :param mealy: MealyMachine 
    :return: 
    """
    copied: Automaton = mealy.copy()

    source: MealyState
    for source in copied.states:
        destination: MealyState
        for _transition, _destination in source.transitions.items():
            pass
        for transition, output in source.output_fun.copy().items():
            if output == NOT_APPLICABLE:
                del source.transitions[transition]
                del source.output_fun[transition]

    return copied
