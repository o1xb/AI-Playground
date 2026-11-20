"""Batch sources. A batch is committed (checkpoint/offset) only after it is fully classified."""


def _records(f, first_line_pattern=None):
    """Lines -> records. With first_line_pattern (Filebeat/elastic-package multiline semantics), a line
    that matches starts a new record and any other line is appended to the current one."""
    import re
    rx = re.compile(first_line_pattern) if first_line_pattern else None
    cur = None
    for raw in f:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if rx is None:
            yield line
            continue
        if rx.search(line) or cur is None:
            if cur is not None:
                yield cur
            cur = line
        else:
            cur += "\n" + line
    if cur is not None:
        yield cur


def file_batches(path, batch_size, start_offset=0, first_line_pattern=None):
    batch, base = [], start_offset
    with open(path, "rb") as f:
        for i, rec in enumerate(_records(f, first_line_pattern)):
            if i < start_offset:
                continue
            batch.append(rec)
            if len(batch) == batch_size:
                yield base, batch
                base += len(batch); batch = []
    if batch:
        yield base, batch


def kafka_batches(bootstrap, topic, group_id, batch_size, idle_ms=5000):
    """Consumes `topic` in batches; commits offsets after the caller finishes each batch (at-least-once).
    Requires `pip install kafka-python`. Not exercised in the test runs here (no broker allowed)."""
    from kafka import KafkaConsumer  # lazy import

    c = KafkaConsumer(topic, bootstrap_servers=bootstrap, group_id=group_id,
                      enable_auto_commit=False, auto_offset_reset="earliest")
    seq = 0
    try:
        while True:
            batch = []
            while len(batch) < batch_size:
                polled = c.poll(timeout_ms=idle_ms, max_records=batch_size - len(batch))
                if not polled:
                    break
                for recs in polled.values():
                    batch.extend(r.value.decode("utf-8", "replace") for r in recs)
            if not batch:
                continue
            yield seq, batch
            c.commit()
            seq += len(batch)
    finally:
        c.close()
