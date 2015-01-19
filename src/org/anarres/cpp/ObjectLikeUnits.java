package org.anarres.cpp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class ObjectLikeUnits extends Unit {
	
	private Macro defMacro;
	private MySegment expanded;
	
	public ObjectLikeUnits(Map<String, Macro>macros, Macro mac) {
		super(macros);
		this.defMacro = mac;
		this.expanded = new MySegment(macros, mac.getTokens());
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
	
	public List<Token> getExpandedTokens() {
		return this.expanded.getExpandedTokens();
	}
}
