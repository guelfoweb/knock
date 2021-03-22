FROM python:3.7-alpine

COPY ./knock /knock
WORKDIR /knock

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "knockpy/knockpy.py"]
