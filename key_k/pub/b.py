
with open("6m.txt","r") as m:
    add = m.read().split()
pub = set(add)

for i in pub:
  x = "".join(i)
  #print(x)
  f=open(u"pub6m.txt","a") 
  f.write(str(x) + '\n')
  f.close()
  
    
  
