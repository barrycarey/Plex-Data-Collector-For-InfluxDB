FROM python
MAINTAINER Andrew Chumchal <andrew@andrewchumchal.com>

VOLUME /src/
COPY plexcollector.py requirements.txt /src/
ADD plexcollector /src/plexcollector
WORKDIR /src

RUN pip install -r requirements.txt

CMD ["python", "-u", "/src/plexcollector.py"]
