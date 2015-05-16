package org.anarres.cpp;

import java.util.List;

public class ChangeFix extends Fix {
	
	private Token tok;
	
	public ChangeFix(int pos, Token tok) {
		super(pos);
		this.tok = tok;
	}
	
	public String toString(){
		return new String("ChangeFix:[" + pos + ", " + this.tok.getText() + "]");
	}
	
	public List<Token> applyFix(List<Token> tl, int base){
		tl.set(pos-base, tok);
		return tl;
	}
}
