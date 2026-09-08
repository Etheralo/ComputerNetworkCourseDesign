import socket
import struct
import unittest

from src.dns_relay.dns_codec import (
    DnsFormatError,
    DnsHeader,
    RCODE_FORMERR,
    build_error_response,
    build_local_a_response,
    build_query,
    decode_name,
    parse_a_answers,
    parse_query,
    response_code,
)


class DnsCodecTests(unittest.TestCase):
    def test_query_round_trip_preserves_name_and_id(self):
        packet = build_query("Example.COM", 0xBEEF)
        query = parse_query(packet)
        self.assertEqual(query.header.transaction_id, 0xBEEF)
        self.assertEqual(query.question.name, "Example.COM")

    def test_local_answer_preserves_transaction_and_question(self):
        packet = build_query("local.test", 0x1234)
        response = build_local_a_response(parse_query(packet), "10.0.0.123")
        header = DnsHeader.from_bytes(response)
        self.assertEqual(header.transaction_id, 0x1234)
        self.assertEqual(header.question_count, 1)
        self.assertEqual(header.answer_count, 1)
        question_wire = parse_query(packet).question.wire
        self.assertEqual(response[12 : 12 + len(question_wire)], question_wire)
        self.assertEqual(parse_a_answers(response), ["10.0.0.123"])

    def test_truncated_question_is_rejected(self):
        with self.assertRaises(DnsFormatError):
            parse_query(build_query("local.test", 1)[:-2])

    def test_compression_pointer_loop_is_rejected(self):
        packet = (
            DnsHeader(1, 0x0100, 1, 0, 0, 0).to_bytes()
            + b"\xc0\x0c"
            + struct.pack("!HH", 1, 1)
        )
        with self.assertRaises(DnsFormatError):
            parse_query(packet)

    def test_formerr_preserves_available_transaction_id(self):
        response = build_error_response(b"\xca\xfe\x01", RCODE_FORMERR)
        self.assertEqual(DnsHeader.from_bytes(response).transaction_id, 0xCAFE)
        self.assertEqual(response_code(response), RCODE_FORMERR)

    def test_decode_name_follows_valid_pointer(self):
        base = build_query("pointer.test", 1)
        name, offset = decode_name(base + b"\xc0\x0c", len(base))
        self.assertEqual(name, "pointer.test")
        self.assertEqual(offset, len(base) + 2)


if __name__ == "__main__":
    unittest.main()
