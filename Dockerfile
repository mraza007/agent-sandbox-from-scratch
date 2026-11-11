FROM public.ecr.aws/docker/library/python:3.11-slim
RUN useradd --create-home --uid 1000 agent
