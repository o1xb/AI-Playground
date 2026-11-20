FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY loggrouper ./loggrouper
COPY prompts ./prompts
# rules/, out/ and state/ are volumes: the rule store must outlive the container
VOLUME ["/data"]
ENTRYPOINT ["python3", "-m", "loggrouper.cli", "--store", "/data/rules", "--out", "/data/out", "--state", "/data/state"]
CMD ["run", "--kafka", "kafka:9092", "--topic", "security-logs", "--batch-size", "20000", \
     "--learner", "agent", "--learn-threshold", "500", "--review-new-labels"]
