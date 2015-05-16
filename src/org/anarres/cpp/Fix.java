package org.anarres.cpp;

import java.util.List;

public class Fix {
	protected int pos;
	
	public Fix() {
		this.pos = -1;
	}
	
	public Fix(int pos) {
		this.pos = pos;
	}
	
	public int getPos() { return this.pos; }
	
	public List<Token> applyFix(List<Token> tl, int base){
		return tl;
	}
}
