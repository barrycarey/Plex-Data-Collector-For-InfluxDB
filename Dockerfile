FROM python:3.3-slim
MAINTAINER Andrew Chumchal <andrew@andrewchumchal.com>

VOLUME /src/
COPY plexcollector.py requirements.txt /src/
WORKDIR /src

RUN pip install -r requirements.txt

CMD ["python", "-u", "/src/plexcollector.py"]
