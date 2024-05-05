FROM python:3.8.1-slim-buster

COPY Pipfile /
COPY Pipfile.lock /

RUN mkdir /plugins \
&& pip install --upgrade pip \
&& pip install pipenv \
&& pipenv install

COPY reflex-agent.py /
COPY utils /utils
COPY module /module
COPY integrations /integrations

CMD ["pipenv", "run", "python", "reflex-agent.py"]
