


from itertools import islice, product

#data = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
data = ['0','1']

for private in islice(product(data, repeat = 3), 0, None):
  
  pr = (''.join(private))
  print(pr)