package org.anarres.cpp;

import java.util.List;

public class DeleteFix extends Fix {
	
	private int end;
	public DeleteFix (int pos) {
		super(pos);
		this.end = pos;
	}
	public DeleteFix (int pos, int end) {
		this(pos);
		this.end = end;
	}
	
	public String toString(){
		return new String("Delete Fix:[" + this.pos + "]");
	}
	
	public List<Token> applyFix(List<Token> tl, int base){
		for (int i = pos; i < end+1; i++) {
			tl.set(i-base, new Token(Token.DELETED));
		}
		return tl;
	}
}
