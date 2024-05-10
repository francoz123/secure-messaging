def is_ascii(s):
  """ Checks that a string is ASCII only"""
  try:
    s.encode("ascii")
    return True
  except UnicodeEncodeError:
    return False