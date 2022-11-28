import numpy as np
from sklearn.linear_model import LinearRegression

age = []
income = []
n = 2000
with open("/afs/andrew.cmu.edu/usr24/jiachend/public/cleaned_small_user_data.csv") as f:
    line = f.readline()
    count = 0
    while count < n:
        line = f.readline()
        if len(line) <= 1:
            break
        line = line.split(',')
        age.append(eval(line[2]))
        income.append(eval(line[3]))
        count += 1

n = len(age)
# age = [2*i for i in range(16)]
# income = [5*i for i in range(16)]

sig_x = sum(age)
sig_y = sum(income)
x2 = [x*x for x in age]
sig_x2 = sum(x2)
sig_xy = sum([age[i] * income[i] for i in range(n)])

a0 = sig_y * sig_x2
a1 = sig_x * sig_xy
a = a0 - a1

b1 = n * sig_xy
b2 = sig_x * sig_y
b = b1 - b2

div1 = n * sig_x2
div2 = sig_x * sig_x
div = div1 - div2 

print("sigy: ", sig_y)
print("sigx2: ", sig_x2)
print("a: ", a)
print("b: ", b)
print("div: ", div)

print("inter: ", a/div)
print("b: ", b/div)

age = np.array(age)
age = np.reshape(age, (-1, 1))

reg = LinearRegression().fit(age, income)
print(reg.coef_, reg.intercept_)