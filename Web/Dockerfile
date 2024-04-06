FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app
# copy all the work from current directory to app
COPY . /app
# install package we need
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 61117

ENV NAME World
CMD ["python", "proxy.py"]

