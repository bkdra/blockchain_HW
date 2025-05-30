from fractions import Fraction

class Point:
    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y**2 != self.x**3 + a*x + b:
            raise ValueError(f'({x}, {y}) is not on the curve')
    
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b
    
    def __ne__(self, other):
        return not (self == other)
    
    def __str__(self):
        if self.x is None:
            return "Point(infinity)"
        else:
            return f"Point({self.x}, {self.y})_{self.a}_{self.b}"
    
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError(f"Points {self} and {other} are not on the same curve")
        
        if self.x is None:                                          # 0 + P_other = P_other
            return other
        if other.x is None:                                         # P_self + 0 = P_self
            return self
        if self.x == other.x and self.y != other.y:                 # P + (-P) = 0
            return self.__class__(None, None, self.a, self.b)
        if self.x != other.x:                                       # P1 != P2
            s = Fraction((other.y - self.y), (other.x - self.x))
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        if self == other:                                           # P1 == P2
            if self.y == 0 * self.x:
                return self.__class__(None, None, self.a, self.b)                             
            s = Fraction((3 * self.x**2 + self.a), (2 * self.y))
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
    
if __name__ == "__main__":
    x1 = int(input("Enter the x-coordinate of the first point: "))
    y1 = int(input("Enter the y-coordinate of the first point: "))
    x2 = int(input("Enter the x-coordinate of the second point: "))
    y2 = int(input("Enter the y-coordinate of the second point: "))
    print("\nelliptic curve: y^2 = x^3 + ax + b: ")
    a = int(input("Enter the a-value of the elliptic curve: "))
    b = int(input("Enter the b-value of the elliptic curve: "))
    P1 = Point(x1, y1, a, b)
    P2 = Point(x2, y2, a, b)
    print("\nPoint 1: ", P1)
    print("Point 2: ", P2)
    print("Curve: y^2 = x^3 + {}x + {}".format(a, b))
    print("({}, {}) + ({}, {}) = ({}, {})".format(P1.x, P1.y, P2.x, P2.y, (P1 + P2).x, (P1 + P2).y))
