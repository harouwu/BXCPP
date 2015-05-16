#define F(x) x + 1
#define G(x) x * 2
#define H(x,y) F(x) + G(y)
#define L(x,y,z) H(F(x y),z)
#define M(x,y) L(x,y,x)
#define N(x,y,z) H(L(x,y,z),G(x y)+F(y z))

int main() {
	H(4,y)
	L(y,x,z)
	M(x,3)
	N(x * 3,y,z)
	H(L(x,y,z),4)
} 