package org.anarres.cpp;

import java.util.ArrayList;
import java.util.List;

public class StringUnits extends Unit {
	
	public StringUnits() {
		super();
	}
	
	public StringUnits(Unit u) {
		this();
		super.setOriginal(u.getOriginal());
		super.setBase(u.getBase());
	}

	@Override
	public void construct() {
		// TODO Auto-generated method stub
		System.out.println("Constructing String Unit...");
		this.expanded = new MySegment(this.original);
		this.length = this.original.size();
		return;
		
	}

	@Override
	public void PrintForward() {
		for (int i = 0; i < this.original.size(); i++) {
			Token tok = this.original.get(i);
			System.out.print(tok.getText());
		}
	}
	
	public List<Token> tokenListForward() {
		return this.original;
	}
	
	@Override
	public int calcBaseLength(){
		return this.original.size();
	}
	
	@Override
	public void PrintBackward(){
		if (!this.changed) {
			for (int i = 0; i < this.original.size(); i++) {
				System.out.print(this.original.get(i).getText());
			}
		}
		else {
			for (int i = 0; i < this.expanded.getBacked().size(); i++) {
				System.out.print(this.expanded.getBacked().get(i).getText());
			}
		}
	}
	
	@Override 
	public Unit mapback(FixList fl){
		if (fl == null) {
			this.expanded.setBacked(this.original);
			return this;
		}
		StringUnits sunit = new StringUnits();
		sunit.setChanged(true);
		sunit.setBroken(true);
		List<Token> tokens = new ArrayList<Token>();
		for (int i = 0; i < this.original.size(); i++) {
			tokens.add(this.original.get(i));
		}
		
		for (int i = 0; i < fl.getFixList().size(); i++) {
			tokens = fl.getFixList().get(i).applyFix(tokens, this.base);
		}
		
		for (int i = 0; i < tokens.size(); i++) {
			if (tokens.get(i).getType() == Token.DELETED) {
				continue;
			}
			sunit.addToken(tokens.get(i));
		}
		sunit.construct();
		sunit.getExpanded().setBacked(sunit.original);
		return sunit;
	}
	@Override
	public boolean equalsBack(Unit unit){
		if (this == unit)
			return true;
		if (unit == null)
			return false;
		if (getClass() != unit.getClass())
			return false;
		if (this.getExpanded().getBacked().size() != unit.getExpanded().getBacked().size()) {
			return false;
		}
		boolean ifStringEquals = true;
		for (int i = 0; i < this.getExpanded().getBacked().size(); i++) {
			ifStringEquals = ifStringEquals && this.getExpanded().getBacked().get(i).getText().equals(unit.getExpanded().getBacked().get(i).getText());
			if (!ifStringEquals) {
				break;
			}
		}
		return ifStringEquals;
	}
	
	@Override
	public int CountMacroCalls() {
		return 0;
	}
}
