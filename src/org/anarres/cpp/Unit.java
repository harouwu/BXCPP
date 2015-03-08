package org.anarres.cpp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class Unit {
	
	protected int base = 0;
	protected int length = 0;
	
	protected boolean changed = false;
	protected boolean broken = false;
	
	protected Map<String, Macro> macros;
	protected List<Token> original;
	protected MySegment expanded;
	
	public Unit(){
		this.macros = new HashMap<String, Macro>();
		this.original = new ArrayList<Token>();
		this.changed = false;
		this.broken = false;
		this.expanded = new MySegment();
	}
	
	public Unit(Map<String, Macro>macros) {
		this();
		this.macros = macros;
	}
	
	/* should override all these */
	public void construct(){}
	public void PrintForward(){}
	public void PrintBackward(){}
	public Unit mapback(FixList fl){ return this; }
	public boolean equalsBack(Unit unit){
		if (this == unit)
			return true;
		if (unit == null)
			return false;
		if (getClass() != unit.getClass())
			return false;
		return this.expanded.equalsBack(unit.getExpanded());
	}
	
	public List<Token> tokenListForward(){
		return new ArrayList<Token>();
	}
	
	public void setOriginal(List<Token> tokens) {
		this.original = tokens;
	}
	
	public List<Token> getOriginal(){
		return this.original;
	}
	
	public MySegment getExpanded() {return this.expanded;}
	
	public void setBase(int b) {this.base = b;}
	public void setLength(int l) {this.length = l;}
	public int getLength() {return this.length;}
	public int getBase() {return this.base;}
	
	public void setChanged(boolean b) {this.changed = b;}
	public boolean isChanged() {return this.changed;}
	
	public void setBroken(boolean b) {this.broken = b;}
	public boolean isBroken() {return this.broken;}
	
	public int calcBaseLength(){return -2;}
	
	
	public void addToken(Token tok){
		original.add(tok);
	}
}
