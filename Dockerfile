FROM python:3.13-slim AS build
WORKDIR /src
COPY toolpass-py/ ./
ARG VERSION=0.0.0
RUN v="${VERSION#v}" \
    && sed -i "s/^__version__ = .*/__version__ = \"${v}\"/" src/toolpass/_version.py \
    && pip wheel --no-cache-dir --no-deps -w /wheels .

FROM python:3.13-slim
# The chart runs the container with a read-only root filesystem: nothing
# may be written at runtime, so the bytecode is compiled at build time.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir "$(ls /wheels/*.whl)[crypto]" \
    && rm -rf /wheels \
    && python -m compileall -q "$(python -c 'import toolpass, os; print(os.path.dirname(toolpass.__file__))')"
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["toolpass"]
CMD ["serve", "-config", "/etc/toolpass/toolpass.yaml"]
