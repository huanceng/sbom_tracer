import six


def decode(string):
    if isinstance(string, six.text_type):
        return string
    elif isinstance(string, (six.binary_type, bytearray)):
        return string.decode("utf-8", errors="replace")
    return string


def batch_decode(string_sequence):
    result_list = []
    for string in string_sequence:
        result_list.append(decode(string))
    return type(string_sequence)(result_list)
