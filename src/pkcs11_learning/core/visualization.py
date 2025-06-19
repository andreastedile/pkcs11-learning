from aalpy import MealyState, MealyMachine

from .abstract_pkcs11_commands import NOT_APPLICABLE


def remove_not_applicable_transitions(mealy: MealyMachine) -> MealyMachine:
    """
    :return: an automaton where transitions corresponding to not applicable commands have been removed.
    """
    copied: MealyMachine = mealy.copy()

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
