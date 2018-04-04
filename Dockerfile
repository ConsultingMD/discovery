FROM ubuntu:16.04

RUN apt update && apt install -y python python-pip python-virtualenv

RUN mkdir -p /etc/discovery
COPY . /etc/discovery

RUN cd /etc/discovery && virtualenv venv && . venv/bin/activate && pip install -r requirements.txt

CMD cd /etc/discovery && . venv/bin/activate && python wsgi.py
