# PKCS #11 learning

## Known attacks

```shell
 python3 known_attacks.py --help
```

Output:

```text
usage: known_attacks.py [-h] [--visualize_automaton] [--hide_same_state_trans] so token_label user_pin

PKCS#11 automaton learning

positional arguments:
  so                    Shared object
  token_label           Token label
  user_pin              User PIN

options:
  -h, --help            show this help message and exit
  --visualize_automaton
                        Visualize the PKCS #11 automaton in the browser after learning
  --hide_same_state_trans
                        Hide same state transitions
```

Example:

```shell
python3 known_attacks.py /usr/local/lib/opencryptoki/libopencryptoki.so primo 1234
```
