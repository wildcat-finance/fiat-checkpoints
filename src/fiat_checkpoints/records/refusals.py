"""Fixed refusal codes that name the producer which emitted them."""

SERVICE = "fiat-checkpoints"
PROTOCOL = "checkpoint-authority"


class RecordRefusal(Exception):
    """One fixed service code; `protocol_code` is set only when the protocol emitted it.

    No input value, path or child diagnostic is carried. A protocol code passes
    through only from a `Refusal` the pinned library raised, never from text.
    """

    def __init__(self, code, *, producer=SERVICE, protocol_code=None, stage=None):
        if producer not in (SERVICE, PROTOCOL) or (producer == PROTOCOL) != (protocol_code is not None):
            raise ValueError("refusal-producer")
        self.code = code
        self.producer = producer
        self.protocol_code = protocol_code
        self.stage = stage
        super().__init__(code)

    def event(self):
        return {"event": "record-refused", "code": self.code, "producer": self.producer,
                "protocol_code": self.protocol_code, "stage": self.stage}


def from_protocol(code, error):
    """Wrap one library `Refusal`; its code and stage are the producer's own values."""
    return RecordRefusal(code, producer=PROTOCOL, protocol_code=error.code, stage=error.stage)
