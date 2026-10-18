# Contributing to Vahini

1. `make install`, then `make test`. Everything must pass before a pull request.
2. Keep the rule intact: nothing a model reads may decide an action. New tools go through `policy.py`, with a risk tier.
3. New connectors live in `src/vahini/connectors/`, map into the Vahini alert shape, and come with a sample in `examples/` and a test.
4. New executors build an `HttpRequest` first and stay dry-run by default.
5. Playbooks in `playbooks/` are reviewed like code. Each one needs at least one attack hypothesis.
6. Never commit real logs, keys or customer data. Use the samples.
