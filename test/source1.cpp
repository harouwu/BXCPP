#define F(x) (x) * x
#define G(x) x + (2 * x)
#define H(x) F(2 x) + G(x)
#define L(x) H(x + 1)
#define M(x) F(G(x) + H(x))
#define N(x) G(L(x) + H(x x)) + F(x)

int main() {
	F(3)
	G(4)
	H(x)
	L(y)
	M(x + 1)
	H(y y) + G(x)
	F(L(x)) 
}