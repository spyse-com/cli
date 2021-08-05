FROM python:3.8

WORKDIR /spysecli

COPY . .

RUN pip3 install .

ENTRYPOINT [ "spysecli" ]