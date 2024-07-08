FROM python:3 as build

WORKDIR /app

RUN mkdir /app/out

COPY out/d3.v4.min.js /app/out/
COPY out/jquery-3.3.1.min.js /app/out/
COPY out/stylesheet-ltr.css /app/out/
COPY out/favicon.ico /app/out/
COPY *.py .
COPY .git .

COPY data/consensus.cfg /app/data/

RUN pip3 install stem
RUN pip3 install pycryptodomex

RUN python3 write_website.py

FROM nginx:1.27

COPY --from=build /app/out /usr/share/nginx/html
