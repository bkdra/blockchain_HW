class FieldElement:
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f"Num {num} not in field range 0 to {prime-1}"
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)
    
    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        num = self.num * pow(other.num, self.prime - 2, self.prime) % self.prime
        return self.__class__(num, self.prime)
    
    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)
    
    def __str__(self):
        return str(self.num)+ '(' + str(self.prime) + ')'

def readEquation(equation):
    oprators = []
    num = []
    tempEquation = equation
    length =  0
    for op in range(len(tempEquation)):
        if tempEquation[op] == '*' or tempEquation[op] == '/' or tempEquation[op] == '^':
            oprators.append(tempEquation[op])
            num.append(equation[:op-length])
            equation = equation[op+1-length:]
            length = op+1
    num.append(equation)
    return num, oprators

def FFoperation(operator, num, operators):
    index = operators.index(operator)
    fieldelement1 = FieldElement(int(num[index]), prime)
    if operator == '^':
        # print(num[index+1])
        # print(fieldelement1)
        result = fieldelement1 ** int(num[index+1])
    elif operator == '*':
        fieldelement2 = FieldElement(int(num[index+1]), prime)
        result = fieldelement1 * fieldelement2
    else:
        fieldelement2 = FieldElement(int(num[index+1]), prime)
        result = fieldelement1 / fieldelement2
    num.pop(index)
    num.pop(index)
    num.insert(index, result.num)
    operators.remove(operator)
    return num, operators

if __name__ == '__main__':
    prime = int(input("Enter the prime number: "))
    equation = input("Enter the equation: ")
    num, operators = readEquation(equation)
    print(num)
    print(operators)
    
    while operators:
        if '^' in operators:
            num, operators = FFoperation('^', num, operators)
        elif '*' in operators:
            num, operators = FFoperation('*', num, operators)
        else:
            num, operators = FFoperation('/', num, operators)
    print("result: ", num[0])