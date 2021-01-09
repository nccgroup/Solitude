import struct

from mitmproxy.utils import strutils


def find_java_ms_timestamps(data):
    import time
    cursor = 0
    timestamps = []
    while cursor < len(data):
        tmp_cursor = cursor
        try:
            timestamp = struct.unpack('>Q', data[tmp_cursor:tmp_cursor + 8])[0]
            tmp_cursor += 8
            t = int(round(time.time() * 1000))
            if t > timestamp > 1262304000000:
                timestamps.append(timestamp)
                cursor = tmp_cursor
            else:
                cursor += 1
        except Exception:
            cursor += 1
    return timestamps


def find_java_strings(data, length_type = 'short'):
    cursor = 0
    strings = []
    while cursor < len(data):
        tmp_cursor = cursor
        try:
            if length_type == 'short':
                token_length = int(struct.unpack('>H', data[cursor:cursor + 2])[0])
                tmp_cursor += 2
            elif length_type == 'char':
                token_length = int(struct.unpack('>B', data[cursor:cursor + 1])[0])
                tmp_cursor += 1
            string_1 = data[tmp_cursor:tmp_cursor + token_length].decode('utf-8')
            tmp_cursor += token_length
            if len(string_1) > 0 and ord(string_1[0]) > 32:
                strings.append(string_1)
                cursor = tmp_cursor
            else:
                cursor += 1
        except Exception:
            cursor += 1
    return strings


def to_hex_lines(data):
    h = strutils.hexdump(data)
    lines = []
    for o, h, s in h:
        lines.append('%s %s %s' % (o, h, s))
    return lines
