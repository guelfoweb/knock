FROM python:2-stretch

WORKDIR /src/app
COPY ./requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN chmod +x ./knockpy/knockpy.py

ENTRYPOINT ["/src/app/knockpy/knockpy.py"]
