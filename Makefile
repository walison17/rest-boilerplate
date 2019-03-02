.PHONY: all serve help test clean install collect docker

COMMAND=python3 manage.py
SETTINGS=inkfeed.settings

all: migrate status serve

withqueue:
	chmod +x bin/dev
	bin/dev

redis:
	redis-server

serve:
	$(COMMAND) runserver --settings=$(SETTINGS)

migrate:
	$(COMMAND) migrate --settings=$(SETTINGS)

migrations:
	$(COMMAND) makemigrations --settings=$(SETTINGS)

# target: help - Display callable targets.
help:
	@egrep "^# target:" [Mm]akefile

# target: test - calls the "test" django command
test:
	$(COMMAND) test --settings=$(SETTINGS)

# target: coverage, works on mac!
coverage:
	coverage run --rcfile=.coveragerc manage.py test
	coverage html
	open ./htmlcov/index.html
	@echo "Run 'serve' in the 'htmlcov' directory to see interactive coverage reports."

# target: clean - remove all ".pyc" files
clean:
	$(COMMAND) clean_pyc --settings=$(SETTINGS)

# target: update - install (and update) pip requirements
install:
	npm install -g mjml
	pip3 install -r requirements.txt

# target: collect - calls the "collectstatic" django command
collect:
	$(COMMAND) collectstatic --settings=$(SETTINGS) --noinput

# target: testwatch, requires entr
testwatch:
	find . | entr $(COMMAND) test --settings=$(SETTINGS)

# target: status, shows info
status:
	$(COMMAND) status --settings=$(SETTINGS)

# celery configuration for local environments
celery:
	celery worker -B -A inkfeed --loglevel=INFO


docker:
	python manage.py status && \
	python manage.py migrate && \
	gunicorn --reload --workers 3 --bind 0.0.0.0:8000 -k uvicorn.workers.UvicornWorker inkfeed.asgi:application