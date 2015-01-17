package org.anarres.cpp;

import java.util.ArrayList;
import java.util.List;

import org.apache.tools.ant.types.Commandline.Argument;

public class Unit {
	
	private List<Token> body;
	private List<Token> original;
	private List<Argument> arguments;
	
	private int type;
	
	public static final int OBJECT_LIKE_MACRO = 301;
	public static final int FUNCTION_LIKE_MACRO = 302;
	public static final int NORMAL = 303;
	
	public Unit() {
		this.original = new ArrayList<Token>();
		this.body = new ArrayList<Token>();
		this.arguments = new ArrayList<Argument>();
	}
	
	public void addToken(Token tok) {
		this.original.add(tok);
	}
	
	public void construction() {
		//seg0 = MyPreprocessor.segment;
		
	}
	
	public int getType(){
		return this.type;
	}
	
	public void setType(int type){
		this.type = type;
	}
	
	public List<Token> getOriginal() {
		return this.original;
	}
	
	public void printOrigin() {
		for (int i = 0; i < this.original.size(); i++) {
			Token token = this.original.get(i);
			System.out.print(token.getText());
		}
	}
}
