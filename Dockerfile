# python runtime
FROM ubuntu
RUN apt-get update
RUN apt-get update -y && \
    apt-get install -y python3-pip python3
#     export LC_ALL=C.UTF-8
#     export LANG=C.UTF-8


COPY ./requirements.txt /app/requirements.txt

# working directory
WORKDIR /app

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

ENV FLASK_APP=/app/app.py
EXPOSE 8080
COPY . /app
RUN pip3 install -r ./requirements.txt

CMD ["flask", "run", "-h","0.0.0.0", "-p", "8080"]






















# FROM alpin:latest
#
# RUN apk update
#
# RUN apk add --no--cache gcc binutils libatomic libgcc libstdc++ gcc libc-dev linux-headers libffl
#
# COPY ./requirements.txt/app/requirements.txt
#
# WORKDIR /app
#
# COPY . /app
#
# EXPOSE 8080
#
# RUN pip3 install -r /app/requirements.txt
#
# RUM rm -r /tmp
# CMD ["flask", "run", "-h","0.0.0.0","-p","8080"]