#define F(x) (x) * x
#define G(x) x + (2 * x)
#define H(x) F(2 x) + G(x)
#define L(x) H(x + 1)
#define M(x) F(G(x) + H(x))
#define N(x) G(L(x) + H(x x)) + F(x)

int main() {
	F(4)
	5 + (3 * 5)
	F(2 y) + z + (2 * x)
	L(z)
	F(G(y + 1))
	(2 y y) * 2 z z + G(y y) + y + (2 * x)
	(L(x)) * F(2 y + 1)
}