import math

from Crypto.Util import number

def lcm(a, b):
    return (a * b) // math.gcd(a, b)

def xgcd(a, b):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def modinv(a, m):
    g, x, y = xgcd(a, m)
    if g != 1:
        return None
    else:
        return x % m

def L(x, n):
    return (x - 1) // n

# 鍵生成アルゴリズム
def paillier_key_gen(bits):
    # 素数p, 素数q
    p = number.getPrime(bits // 2)
    while True:
        q = number.getPrime(bits // 2)
        if p != q:
            break
    n = p * q
    λ = lcm(p-1, q-1)
    # 原始元g
    while True:
        g = number.getRandomRange(2, n*n)
        μ = modinv(L(pow(g, λ, n*n), n) % n, n)
        if μ is not None:
            break
    return (n, g), (λ, μ)

# 暗号化アルゴリズム
def paillier_encrypt(m, pk):
    n, g = pk
    nn = n * n
    assert(0 <= m < n)
    while True:
        r = number.getRandomRange(2, n)
        if math.gcd(r, n) == 1:
            break
    return (pow(g, m, nn) * pow(r, n, nn)) % nn

# 復号アルゴリズム
def paillier_decrypt(c, pk, sk):
    n, g = pk
    λ, μ = sk
    assert(0 <= c < n*n)
    return (L(pow(c, λ, n*n), n) * μ) % n


# 鍵ペアの生成
pk, sk = paillier_key_gen(bits=40)
n, _ = pk
print('pk:', pk)
print('sk:', sk)
print()

# 暗号化して復号化
m = 3141592
print('m:', m)
c = paillier_encrypt(m, pk)
print('c:', c)
d = paillier_decrypt(c, pk, sk)
print('d:', d) # => 3141592

# 加法準同型性
m1 = 3
c1 = paillier_encrypt(m1, pk)
m2 = 7
c2 = paillier_encrypt(m2, pk)
print('m1:', m1)
print('m2:', m2)
print('c1:', c1)
print('c2:', c2)
c = (c1 * c2) % (n*n)
print('c1*c2:', c)
d = paillier_decrypt(c, pk, sk)
print('d:', d)

# 乗法準同型暗号
m1 = 5
c1 = paillier_encrypt(m1, pk)
m2 = 9
print('m1:', m1)
print('m2:', m2)
print('c1:', c1)
c = pow(c1, m2, n*n)
print('c1*c2:', c)
d = paillier_decrypt(c, pk, sk)
print('d:', d)
