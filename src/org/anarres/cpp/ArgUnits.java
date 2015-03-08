package org.anarres.cpp;

import java.util.List;
import java.util.Map;

public class ArgUnits extends Unit {
	
	public ArgUnits() {
		super();
		this.expanded = new MySegment();
	}
	
	public ArgUnits(MySegment arg) {
		this();
		this.expanded = new MySegment(arg.getMacros(), arg.getTokens(), arg.getArgs());
	}
	
	public ArgUnits(MySegment arg, Map<String, Macro> macros) {
		this(arg);
		this.expanded.setMacros(macros);
	}
	
	public ArgUnits(MySegment seg, boolean ifback){
		this();
		this.expanded = seg;
		this.broken = seg.isBroken();
		this.changed = seg.isChanged();
	}
	
	@Override
	public void construct(){
		/*
		 * do nothing here because the arg has already constructed before. */
		this.expanded.mySplit();
		return;
	}
	
	@Override
	public int calcBaseLength(){
		this.expanded.setBase(this.base);
		return this.length = this.expanded.calcBaseLength();
	}
	
	@Override
	public void PrintForward(){
		this.expanded.PrintForward();
		return;
	}
	public List<Token> tokenListForward(){
		return this.expanded.tokenListForward();
	}
	
	@Override
	public void PrintBackward(){
		if (!this.changed) {
			for (int i = 0; i < this.original.size(); i++) {
				//System.out.print(this.original.get(i).getText());
				this.expanded.ArgPrintBack();
			}
		}
		else {
			this.expanded.PrintBackward();
		}
	}
	
	@Override
	public Unit mapback(FixList fl){
		if (fl == null) {
			this.expanded.setBacked(this.original);
			return this;
		}
		MySegment segment = this.expanded.mapback(fl);
		ArgUnits aunit = new ArgUnits(segment, true);
		return aunit;
	}
	
	@Override
	public boolean equalsBack(Unit unit) {
		if (this == unit)
			return true;
		if (unit == null)
			return false;
		if (getClass() != unit.getClass())
			return false;
		return this.expanded.equalsBack(unit.getExpanded());
	}
}
