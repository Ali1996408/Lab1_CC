import re
from sympy import symbols, Eq, solve
from pyformlang.finite_automaton import NondeterministicFiniteAutomaton
from pyformlang.regular_expression import Regex


def parse_grammar(grammar_rules):
    equations = {}
    for rule in grammar_rules:
        lhs, rhs = rule.split("->")
        lhs = lhs.strip()
        rhs_parts = rhs.split("|")
        if lhs not in equations:
            equations[lhs] = []
        equations[lhs].extend([part.strip() for part in rhs_parts])
    return equations


def build_equations(equations):
    regex_vars = {var: Regex(var) for var in equations.keys()}
    regex_exprs = {}
    for var, productions in equations.items():
        regex_expr = None
        for production in productions:
            production_regex = None
            for symbol in production:
                if symbol.isupper():
                    if production_regex is None:
                        production_regex = regex_vars[symbol]
                    else:
                        production_regex = production_regex.concatenate(regex_vars[symbol])
                else:
                    if production_regex is None:
                        production_regex = Regex(symbol)
                    else:
                        production_regex = production_regex.concatenate(Regex(symbol))
            if regex_expr is None:
                regex_expr = production_regex
            else:
                regex_expr = regex_expr.union(production_regex)
        regex_exprs[var] = regex_expr
    return regex_exprs, regex_vars


def solve_equations(equations, vars):
    solutions = {}
    for var, expr in equations.items():
        minimized_regex = expr.to_epsilon_nfa().minimize().to_regex()
        solutions[var] = minimized_regex
    return solutions


def regex_to_nfa(regex):
    regex_obj = Regex(regex)
    return regex_obj.to_epsilon_nfa()


def determinize_nfa(nfa):
    dfa = nfa.to_deterministic()
    return dfa


if __name__ == "__main__":
    grammar_rules = [
        "S -> aB | bA",
        "A -> a | aS | bAA",
        "B -> b | bS | aBB"
    ]

    equations = parse_grammar(grammar_rules)
    regex_exprs, regex_vars = build_equations(equations)
    solved_eqs = solve_equations(regex_exprs, regex_vars)

    for var, solution in solved_eqs.items():
        print(f"{var} = {solution}")

    main_regex = str(solved_eqs['S'])
    nfa = regex_to_nfa(main_regex)
    print("НКА построен")

    dfa = determinize_nfa(nfa)
    print("НКА детерминизирован в ДКА")
