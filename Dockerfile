FROM python:3.8.1-slim-buster

COPY reflex-agent.py /
COPY Pipfile /
COPY Pipfile.lock /
COPY utils /utils
COPY module /module
COPY integrations /integrations

RUN mkdir /plugins \
&& pip install --upgrade pip \
&& pip install pipenv \
&& pipenv install

CMD ["pipenv", "run", "python", "reflex-agent.py"]
