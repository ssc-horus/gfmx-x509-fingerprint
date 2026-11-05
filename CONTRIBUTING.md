# Contributing

The public GFMX repository is read-only: it does not accept pull requests, issues or other outside contributions, and it is updated only by SecurityScorecard's releases. Report security problems privately as described in [SECURITY.md](SECURITY.md). For commercial licensing or other questions, contact [Gilad Friedenriech Maizles](mailto:gilad.maizles@securityscorecard.io).

## Running the tests

```bash
python3 tests/test_vectors.py                       # conformance, no dependencies
pip install -r testbench/requirements.txt
python3 testbench/selfsig_test.py                   # 34 algorithm and curve cases
python3 testbench/serial_test.py
bash testbench/run_test.sh /tmp/bench --seed 1      # blueprints + noise
(cd go && go vet ./... && go test ./...)
(cd go && go build -o /tmp/gfmx ./cmd/gfmx)
python3 testbench/mutate.py /tmp/mut 20000 1 && python3 testbench/crosscheck.py /tmp/gfmx /tmp/mut
```

An independent implementation in another language conforms when it reproduces `testdata/vectors.jsonl` exactly and passes `crosscheck.py` against the reference.
