"""Tests for the stdio connector (unit tests with mock, no real subprocess)."""

import asyncio
import json

from mcpfuzz.utils.jsonrpc import make_request, make_notification, parse_response


def test_make_request():
    req_id, req_str = make_request("initialize", {"protocolVersion": "2024-11-05"})
    msg = json.loads(req_str)
    assert msg["jsonrpc"] == "2.0"
    assert msg["id"] == req_id
    assert msg["method"] == "initialize"
    assert msg["params"]["protocolVersion"] == "2024-11-05"


def test_make_notification():
    notif_str = make_notification("notifications/initialized")
    msg = json.loads(notif_str)
    assert msg["jsonrpc"] == "2.0"
    assert "id" not in msg
    assert msg["method"] == "notifications/initialized"


def test_parse_response():
    resp_str = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": []},
    })
    parsed = parse_response(resp_str)
    assert parsed["id"] == 1
    assert parsed["result"]["tools"] == []


def test_request_ids_increment():
    id1, _ = make_request("test1")
    id2, _ = make_request("test2")
    assert id2 > id1
