from itertools import islice, product

data = ['x1','x2','x3','x4','x5','x6']
#for private in islice(product('0123456789abcdef', repeat = 3), 0, None):
 # pr = (''.join(private))
 # print(f'{pr}')
  
from itertools import permutations

def generate_permutations(my_list, length=None):
    if length is None:
        permutations_list = permutations(my_list)
    else:
        permutations_list = permutations(my_list, length)
    n = 0
    for perm in permutations_list:
        n+=1
        pr = (' + '.join(perm))
        #print(f'x_{n} = {pr}')
        print(f'print(x_{n})')

# Contoh penggunaan
# Juga bisa dengan panjang permutasi yang disesuaikan
generate_permutations(data, 3)

