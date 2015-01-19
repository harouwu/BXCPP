package org.anarres.cpp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class Unit {
	
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
	public List<Token> getExpandedTokens(){return this.original;};
	
	public void setOriginal(List<Token> tokens) {
		this.original = tokens;
	}
	
	public List<Token> getOriginal(){
		return this.original;
	}
	
	
	
	public void addToken(Token tok){
		original.add(tok);
	}
}
