# PKCS #11 learning

```shell
python3 learn_clulow.py --help
```

Output:

```text
usage: learn_clulow.py [-h] --n_iter N_ITER [--no_pruning] [--debug] [--visualize_automaton] [--display_same_state_trans] so token_label user_pin

PKCS#11 automaton learning

positional arguments:
  so                    Shared object
  token_label           Token label
  user_pin              User PIN

options:
  -h, --help            show this help message and exit
  --n_iter N_ITER       Number of graph expansion iterations (int)
  --no_pruning          Disable graph pruning
  --debug               Save the graph generation steps to PNG for debugging
  --visualize_automaton
                        Visualize the PKCS #11 automaton after learning
  --display_same_state_trans
                        Display same state transitions
```

Example:

```shell
python3 learn_clulow.py /usr/local/lib/opencryptoki/libopencryptoki.so primo 1234 --n_iter 3
```
