import secrets

lower_bound = 8589934592
upper_bound = 12884901887


for i in range(10):
  r = secrets.choice(range(lower_bound, upper_bound))
  s = hex(r)[2:] + "00000000"
  e = hex(r)[2:] + "ffffffff"
  print(f"{s}:{e}")