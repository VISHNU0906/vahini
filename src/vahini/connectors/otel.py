"""OTLP/JSON traces to the flat span dicts AgentWatch reads.

The OpenTelemetry Collector's file exporter (and OTLP/HTTP JSON) nests spans as
``resourceSpans[].scopeSpans[].spans[]`` with attributes as
``[{"key": ..., "value": {"stringValue" | "intValue" | ...: ...}}]``.
"""

from __future__ import annotations

from typing import Any, Iterator

_VALUE_KEYS = ("stringValue", "intValue", "doubleValue", "boolValue")


def _value(v: dict[str, Any]) -> Any:
    for key in _VALUE_KEYS:
        if key in v:
            return int(v[key]) if key == "intValue" else v[key]
    if "arrayValue" in v:
        return [_value(x) for x in v["arrayValue"].get("values", [])]
    return None


def flatten(otlp: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for rs in otlp.get("resourceSpans", []):
        service = next((_value(a["value"]) for a in rs.get("resource", {}).get("attributes", [])
                        if a.get("key") == "service.name"), None)
        for ss in rs.get("scopeSpans", []):
            for sp in ss.get("spans", []):
                attrs = {a["key"]: _value(a["value"]) for a in sp.get("attributes", [])}
                yield {
                    "trace_id": sp.get("traceId"),
                    "span_id": sp.get("spanId"),
                    "parent_id": sp.get("parentSpanId"),
                    "name": sp.get("name"),
                    "service": service,
                    "start_time": int(sp.get("startTimeUnixNano", 0)),
                    "attributes": attrs,
                }


def group_by_trace(spans: Iterator[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    traces: dict[str, list[dict[str, Any]]] = {}
    for s in spans:
        traces.setdefault(s["trace_id"], []).append(s)
    return traces
