package org.anarres.cpp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class Unit {
	
	protected int base = 0;
	protected int length = 0;
	
	private Map<String, Macro> macros;
	private List<Token> original;
	
	public Unit(){
		this.macros = new HashMap<String, Macro>();
		this.original = new ArrayList<Token>();
	}
	
	public Unit(Map<String, Macro>macros) {
		this();
		this.macros = macros;
	}
	
	/* should override all these */
	public void construct(){}
	public void PrintForward(){}
	public void PrintBackward(){}
	
	public void setOriginal(List<Token> tokens) {
		this.original = tokens;
	}
	
	public List<Token> getOriginal(){
		return this.original;
	}
	
	public void setBase(int b) {this.base = b;}
	public void setLength(int l) {this.length = l;}
	public int getLength() {return this.length;}
	public int getBase() {return this.base;}
	
	
	public void addToken(Token tok){
		original.add(tok);
	}
}
