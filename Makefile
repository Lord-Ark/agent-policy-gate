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
	PYTHONPATH=$(PYTHONPATH) PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m unittest discover -s tests -v

security:
	PYTHONPATH=$(PYTHONPATH) PYTHONPYCACHEPREFIX=$(PYCACHE) $(PYTHON) -m agent_policy_gate.cli evaluate --policy examples/policy.json --trace examples/trace.json --format json > /tmp/apg-security-check.json

verify: format lint typecheck test security
