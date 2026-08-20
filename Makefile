PYTHON ?= python3
PYTHONPATH := src
PYCACHE := .pycache

.PHONY: format lint typecheck test security verify

format:
	PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m compileall src tests

lint:
	PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m py_compile src/agent_policy_gate/*.py tests/*.py

typecheck:
	PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m py_compile src/agent_policy_gate/*.py

test:
	PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m unittest discover -s tests -t . -v

security:
	PYTHONPATH=$(PYTHONPATH) PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m agent_policy_gate.cli validate --policy examples/policy.json
	PYTHONPATH=$(PYTHONPATH) PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m agent_policy_gate.cli evaluate --policy examples/policy.json --trace examples/trace.json --format sarif --output /tmp/apg-security-check.sarif
	PYTHONPATH=$(PYTHONPATH) PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m agent_policy_gate.cli evaluate --policy examples/policy.json --trace examples/trace.json --fail-on deny || test $$? -eq 3

verify: format lint typecheck test security
