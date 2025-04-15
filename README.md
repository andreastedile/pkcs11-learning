# PKCS #11 learning

## Run an attack

```shell
python learn_known_attacks.py -h
```

Output:

```text
usage: learn_known_attacks.py [-h] so token_label user_pin

PKCS#11 automaton learning

positional arguments:
  so           Shared object
  token_label  Token label
  user_pin     User PIN

options:
  -h, --help   show this help message and exit
```

Example:

```shell
python learn_known_attacks.py /usr/local/lib/opencryptoki/libopencryptoki.so primo 1234
```

## Remove all results

```shell
./cleanup.sh
```

## Compare HSM models

First, convert dot files to the aut format: https://mcrl2.org/web/user_manual/tools/lts.html.
For example:

```shell
python3 lts.py model.dot
``` 

Then:

```shell
ltscompare --counter-example --preorder=trace-ac model2.aut model1.aut
tracepp --format=plain counter_example_trace_preorder.trc
```
