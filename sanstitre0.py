def collatz (n):
    l=[]
    while (n!=1) :
        if (n%2==0):
            l.append(n/2)
            n=n/2
        else :
            l.append((3*n)+1)
            n=(3*n)+1
    return l


def test():
    max=0
    l=0
    max2=0
    for i in range (1,1000000):
        l=len(collatz(i))
        if (l>max):
            max=l
            max2=i
    return max2


print(test())