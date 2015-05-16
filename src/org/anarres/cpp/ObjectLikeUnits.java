package org.anarres.cpp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class ObjectLikeUnits extends Unit {
	
	private Macro defMacro;
	
	public ObjectLikeUnits(Map<String, Macro>macros, Macro mac) {
		super(macros);
		this.defMacro = mac;
		this.expanded = new MySegment(macros, mac.getTokens());
	}
	
	public ObjectLikeUnits(MySegment seg, Macro mac){
		super(seg.getMacros());
		this.defMacro = mac;
		this.expanded = seg;
		this.broken = seg.isBroken();
		this.changed = seg.isChanged();
	}
	
	@Override
	public void construct(){
		System.out.println("Constructing an Obj Macro...");
		this.expanded.mySplit();
	}
	
	@Override
	public void PrintForward(){
		this.expanded.PrintForward();
	}
	public List<Token> tokenListForward(){
		return this.expanded.tokenListForward();
	}
	
	@Override
	public int calcBaseLength(){
		this.expanded.setBase(this.base);
		return this.length = this.expanded.calcBaseLength();
	}
	
	@Override
	public int CountMacroCalls() {
		int mcc = 1;
		mcc += this.expanded.CountMacroCalls();
		return mcc;
	}	
	
	@Override
	public int CountMacroCallsBack() {
		int mcc = 0;
		if (!this.changed) mcc = 1;
		mcc += this.expanded.CountMacroCallsBack();
		return mcc;
	}	
	
	@Override
	public void PrintBackward(){
		if (!this.changed) {
			for (int i = 0; i < this.original.size(); i++) {
				System.out.print(this.original.get(i).getText());
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
		ObjectLikeUnits ounit = new ObjectLikeUnits(segment, this.defMacro);
		return ounit;
	}
	
	@Override
	public boolean equalsBack(Unit unit){
		if (this == unit)
			return true;
		if (unit == null)
			return false;
		if (getClass() != unit.getClass())
			return false;
		return this.expanded.equalsBack(unit.getExpanded());
	}
}
