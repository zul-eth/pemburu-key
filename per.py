
  
  
#
priv = 18446744073579551615
for i in range(100000000):
    priv-=1
    my_priv = "%016x" % priv
    should_print = True
    for j in range(len(my_priv) - 2):
        if my_priv[j] == my_priv[j+1] and my_priv[j] == my_priv[j+2]:
            should_print = False
            break
    if should_print:
        print(f'{my_priv}')
