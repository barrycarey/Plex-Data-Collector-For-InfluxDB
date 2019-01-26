FROM python
MAINTAINER Andrew Chumchal <andrew@andrewchumchal.com>

VOLUME /src/
COPY plexcollector.py requirements.txt /src/
COPY config.ini /src/config.example.ini
ADD plexcollector /src/plexcollector
WORKDIR /src

RUN pip install -r requirements.txt

CMD ["python3", "-u", "/src/plexcollector.py"]
