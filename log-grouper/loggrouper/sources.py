"""Batch sources. A batch is committed (checkpoint/offset) only after it is fully classified."""


def file_batches(path, batch_size, start_offset=0):
    batch, base = [], start_offset
    with open(path, "rb") as f:
        for i, raw in enumerate(f):
            if i < start_offset:
                continue
            batch.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
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
